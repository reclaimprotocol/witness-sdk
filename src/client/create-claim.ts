import { strToUint8Array, TLSPacketContext } from '@reclaimprotocol/tls'
import { makeRpcTlsTunnel } from 'src/client/tunnels/make-rpc-tls-tunnel'
import { getAttestorClientFromPool } from 'src/client/utils/attestor-pool'
import { DEFAULT_HTTPS_PORT } from 'src/config'
import { ClaimTunnelRequest, ZKProofEngine } from 'src/proto/api'
import { providers } from 'src/providers'
import { CreateClaimOnAttestorOpts, IAttestorClient, MessageRevealInfo, ProviderName, Transcript } from 'src/types'
import {
	AttestorError,
	canonicalStringify,
	generateTunnelId,
	getBlocksToReveal,
	getProviderValue,
	isApplicationData,
	logger as LOGGER,
	makeHttpResponseParser,
	preparePacketsForReveal,
	redactSlices,
	unixTimestampSeconds
} from 'src/utils'
import { executeWithRetries } from 'src/utils/retries'
import { SIGNATURES } from 'src/utils/signatures'
import { getDefaultTlsOptions } from 'src/utils/tls'

type ServerAppDataPacket = {
	plaintext: Uint8Array
	message: TLSPacketContext
}

/**
 * Create a claim on the attestor
 */
export function createClaimOnAttestor<N extends ProviderName>(
	{ logger: _logger, ...opts }: CreateClaimOnAttestorOpts<N>
) {
	const logger = _logger
		// if the client has already been initialised
		// and no logger is provided, use the client's logger
		// otherwise default to the global logger
		|| ('logger' in opts.client ? opts.client.logger : LOGGER)
	return executeWithRetries(
		attempt => (
			_createClaimOnAttestor<N>({
				...opts,
				logger: attempt
					? logger.child({ attempt })
					: logger
			})
		),
		{ logger, shouldRetry }
	)
}

function shouldRetry(err: Error) {
	if(err instanceof TypeError) {
		return false
	}

	return err instanceof AttestorError
		&& err.code !== 'ERROR_INVALID_CLAIM'
		&& err.code !== 'ERROR_BAD_REQUEST'
}

async function _createClaimOnAttestor<N extends ProviderName>(
	{
		name,
		params,
		secretParams,
		context,
		onStep,
		ownerPrivateKey,
		client: clientInit,
		logger = LOGGER,
		timestampS,
		updateProviderParams,
		...zkOpts
	}: CreateClaimOnAttestorOpts<N>
) {
	const provider = providers[name]
	const hostPort = getProviderValue(params, provider.hostPort)
	const geoLocation = getProviderValue(params, provider.geoLocation)
	const providerTlsOpts = getProviderValue(
		params,
		provider.additionalClientOptions
	)
	const tlsOpts = {
		...getDefaultTlsOptions(),
		...providerTlsOpts,
	}

	let redactionMode = getProviderValue(params, provider.writeRedactionMode)

	const [host, port] = hostPort.split(':')
	const resParser = makeHttpResponseParser()

	let client: IAttestorClient
	let lastMsgRevealed = false

	const revealMap = new Map<TLSPacketContext, MessageRevealInfo>()

	onStep?.({ name: 'connecting' })

	let endedHttpRequest: ((err?: Error) => void) | undefined
	const createTunnelReq = {
		host,
		port: port ? +port : DEFAULT_HTTPS_PORT,
		geoLocation,
		id: generateTunnelId()
	}

	const tunnel = await makeRpcTlsTunnel({
		tlsOpts,
		connect: (initMessages) => {
			let created = false
			if('metadata' in clientInit) {
				client = clientInit
			} else {
				client = getAttestorClientFromPool(
					clientInit.url,
					() => {
						created = true
						return { initMessages, logger }
					}
				)
			}

			if(!created) {
				client
					.waitForInit()
					.then(() => client.sendMessage(...initMessages))
					.catch(err => {
						logger.error(
							{ err },
							'error in sending init msgs'
						)
					})
			}

			return client
		},
		logger,
		request: createTunnelReq,
		onMessage(data) {
			logger.debug({ bytes: data.length }, 'recv data from server')

			resParser.onChunk(data)
			if(resParser.res.complete) {
				logger?.debug('got complete HTTP response from server')
				// wait a little bit to make sure the client has
				// finished writing the response
				setTimeout(() => {
					endedHttpRequest?.()
				}, 100)
			}
		},
		onClose(err) {
			const level = err ? 'error' : 'debug'
			logger?.[level]({ err }, 'tls session ended')
			endedHttpRequest?.(err)
			try {
				resParser.streamEnded()
			} catch{ }
		},
	})
	const {
		version: tlsVersion,
		cipherSuite
	} = tunnel.tls.getMetadata()
	if(tlsVersion === 'TLS1_2' && redactionMode !== 'zk') {
		redactionMode = 'zk'
		logger.info('TLS1.2 detected, defaulting to zk redaction mode')
	}

	const {
		redactions,
		data: requestStr
	} = provider.createRequest(
		// @ts-ignore
		secretParams,
		params
	)
	const requestData = typeof requestStr === 'string'
		? strToUint8Array(requestStr)
		: requestStr

	logger.debug(
		{ redactions: redactions.length },
		'generated request'
	)

	const waitForAllData = new Promise<void>(
		(resolve, reject) => {
			endedHttpRequest = err => (
				err ? reject(err) : resolve()
			)
		}
	)

	onStep?.({ name: 'sending-request-data' })

	try {
		if(redactionMode === 'zk') {
			await writeRedactedZk()
		} else {
			await writeRedactedWithKeyUpdate()
		}

		logger.info('wrote request to server')
	} catch(err) {
		// wait for complete stream end when the session is closed
		// mid-write, as this means the server could not process
		// our request due to some error. Hope the stream end
		// error will be more descriptive
		logger.error(
			{ err },
			'session errored during write, waiting for stream end'
		)
	}

	onStep?.({ name: 'waiting-for-response' })

	await waitForAllData
	await tunnel.close()

	logger.info('got full response from server')

	// update the response selections
	if(updateProviderParams) {
		const { params:updatedParms, secretParams:updatedSecretParms } = await updateProviderParams(tunnel.transcript, tlsVersion ?? 'TLS1_2')
		params = { ...params, ...updatedParms }
		secretParams = { ...secretParams, ...updatedSecretParms }
	}

	const signatureAlg = SIGNATURES[client!.metadata.signatureType]

	let serverIV: Uint8Array
	let clientIV: Uint8Array
	const serverBlock = getLastBlock('server')
	if(serverBlock && serverBlock.message.type === 'ciphertext') {
		serverIV = serverBlock.message.fixedIv
	}

	const clientBlock = getLastBlock('client')
	if(clientBlock && clientBlock.message.type === 'ciphertext') {
		clientIV = clientBlock.message.fixedIv
	}


	// now that we have the full transcript, we need
	// to generate the ZK proofs & send them to the attestor
	// to verify & sign our claim
	const claimTunnelReq = ClaimTunnelRequest.create({
		request: createTunnelReq,
		data: {
			provider: name,
			parameters: canonicalStringify(params),
			context: canonicalStringify(context),
			timestampS: timestampS ?? unixTimestampSeconds(),
			owner: getAddress(),
		},
		transcript: await generateTranscript(),
		zkEngine: zkOpts.zkEngine === 'gnark' ? ZKProofEngine.ZK_ENGINE_GNARK : ZKProofEngine.ZK_ENGINE_SNARKJS,
		fixedServerIV: serverIV!,
		fixedClientIV: clientIV!,
	})

	onStep?.({ name: 'waiting-for-verification' })

	const claimTunnelBytes = ClaimTunnelRequest
		.encode(claimTunnelReq).finish()
	const requestSignature = await signatureAlg
		.sign(claimTunnelBytes, ownerPrivateKey)
	claimTunnelReq.signatures = { requestSignature }

	const result = await client!.rpc('claimTunnel', claimTunnelReq)

	logger.info({ success: !!result.claim }, 'recv claim response')

	return result

	async function writeRedactedWithKeyUpdate() {
		let currentIndex = 0
		for(const section of redactions) {
			const block = requestData
				.slice(currentIndex, section.fromIndex)
			if(block.length) {
				await writeWithReveal(block, true)
			}

			const redacted = requestData
				.slice(section.fromIndex, section.toIndex)
			await writeWithReveal(redacted, false)
			currentIndex = section.toIndex
		}

		// write if redactions were there
		const lastBlockStart = redactions?.[redactions.length - 1]
			?.toIndex || 0
		const block = requestData.slice(lastBlockStart)
		if(block.length) {
			await writeWithReveal(block, true)
		}
	}

	async function writeRedactedZk() {
		await tunnel.tls.write(requestData)
		setRevealOfLastSentBlock(
			{
				type: 'zk',
				redactedPlaintext: redactSlices(requestData, redactions)
			}
		)
	}

	/**
	 * Write data to the tunnel, with the option to mark the packet
	 * as revealable to the attestor or not
	 */
	async function writeWithReveal(data: Uint8Array, reveal: boolean) {
		// if the reveal state has changed, update the traffic keys
		// to not accidentally reveal a packet not meant to be revealed
		// and vice versa
		if(reveal !== lastMsgRevealed) {
			await tunnel.tls.updateTrafficKeys()
		}

		await tunnel.write(data)
		// now we mark the packet to be revealed to the attestor
		setRevealOfLastSentBlock(reveal ? { type: 'complete' } : undefined)
		lastMsgRevealed = reveal
	}

	function setRevealOfLastSentBlock(
		reveal: MessageRevealInfo | undefined
	) {
		const lastBlock = getLastBlock('client')
		if(!lastBlock) {
			return
		}

		setRevealOfMessage(lastBlock.message, reveal)
	}

	function getLastBlock(sender: 'client' | 'server') {
		// set the correct index for the server blocks
		for(let i = tunnel.transcript.length - 1;i >= 0;i--) {
			const block = tunnel.transcript[i]
			if(block.sender === sender) {
				return block
			}
		}
	}

	/**
	 * Generate transcript with reveal data for the attestor to verify
	 */
	async function generateTranscript() {
		addServerSideReveals()

		const startMs = Date.now()
		const revealedMessages = await preparePacketsForReveal(
			tunnel.transcript,
			revealMap,
			{
				logger,
				cipherSuite: cipherSuite!,
				onZkProgress(done, total) {
					const timeSinceStartMs = Date.now() - startMs
					const timePerBlockMs = timeSinceStartMs / done
					const timeLeftMs = timePerBlockMs * (total - done)
					onStep?.({
						name: 'generating-zk-proofs',
						proofsDone: done,
						proofsTotal: total,
						approxTimeLeftS: Math.round(timeLeftMs / 1000),
					})
				},
				...zkOpts,
			}
		)

		return revealedMessages
	}

	/**
	 * Add reveals for server side blocks, using
	 * the provider's redaction function if available.
	 * Otherwise, opts to reveal all server side blocks.
	 */
	function addServerSideReveals() {
		const allPackets = tunnel.transcript
		let serverPacketsToReveal: ReturnType<typeof getBlocksToReveal<ServerAppDataPacket>> = 'all'

		const packets: Transcript<Uint8Array> = []
		const serverBlocks: ServerAppDataPacket[] = []
		for(const b of allPackets) {
			if(b.message.type !== 'ciphertext'
				|| !isApplicationData(b.message, tlsVersion)
			) {
				continue
			}

			const plaintext = tlsVersion === 'TLS1_3'
				? b.message.plaintext.slice(0, -1)
				: b.message.plaintext

			packets.push({
				message: plaintext,
				sender:b.sender
			})

			if(b.sender === 'server') {
				serverBlocks.push({
					plaintext:plaintext,
					message: b.message
				})
			}
		}

		if(provider.getResponseRedactions) {
			serverPacketsToReveal = getBlocksToReveal(
				serverBlocks,
				total => provider.getResponseRedactions!(
					total,
					params
				)
			)
		}

		const revealedPackets: Transcript<Uint8Array> = packets.filter(p => p.sender === 'client')
		if(serverPacketsToReveal === 'all') {
			// reveal all server side blocks
			for(const { message, sender } of allPackets) {
				if(sender === 'server') {
					setRevealOfMessage(message, { type: 'complete' })
				}
			}

			revealedPackets.push(...packets.filter(p => p.sender === 'server'))
		} else {
			for(const { block, redactedPlaintext } of serverPacketsToReveal) {
				setRevealOfMessage(block.message, {
					type: 'zk',
					redactedPlaintext
				})
				revealedPackets.push({ sender:'server', message:redactedPlaintext })
			}
		}

		provider.assertValidProviderReceipt(revealedPackets, {
			...params,
			secretParams:secretParams //provide secret params for proper request body validation
		})

		// reveal all handshake blocks
		// so the attestor can verify there was no
		// hanky-panky
		for(const p of allPackets) {
			if(p.message.type !== 'ciphertext') {
				continue
			}

			// break the moment we hit the first
			// application data packet
			if(isApplicationData(p.message, tlsVersion)) {
				break
			}

			setRevealOfMessage(p.message, { type: 'complete' })
		}
	}

	function setRevealOfMessage(message: TLSPacketContext, reveal: MessageRevealInfo | undefined) {
		if(reveal) {
			revealMap.set(message, reveal)
			return
		}

		revealMap.delete(message)
	}

	function getAddress() {
		const {
			getAddress,
			getPublicKey,
		} = signatureAlg
		const pubKey = getPublicKey(ownerPrivateKey)
		return getAddress(pubKey)
	}
}