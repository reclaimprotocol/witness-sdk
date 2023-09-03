import {
	generateProof,
	makeLocalSnarkJsZkOperator,
	makeRemoteSnarkJsZkOperator,
	toUint8Array,
	toUintArray,
	verifyProof,
	ZKOperator
} from '@reclaimprotocol/circom-chacha20'
import { detectEnvironment } from '@reclaimprotocol/common-grpc-web-transport'
import { MAX_ZK_CHUNKS } from '../config'
import { FinaliseSessionRequest_Block as BlockReveal, FinaliseSessionRequest_BlockRevealZk } from '../proto/api'
import { ArraySlice, Logger } from '../types'
import { logger as LOGGER } from './logger'
import { getBlocksToReveal, isFullyRedacted, isRedactionCongruent, REDACTION_CHAR_CODE } from './redactions'

const CHACHA_BLOCK_SIZE = 64

type ZKChunk = {
	chunk: Uint8Array
	counter: number
}

type BlockWithPlaintext = Partial<BlockReveal> & {
	ciphertext: Uint8Array
	plaintext: Uint8Array
}

type ZKBlock = {
	block: BlockWithPlaintext
	redactedPlaintext: Uint8Array
	zkChunks: ZKChunk[]
}

type PrepareZKProofsOpts = {
	/** blocks to prepare ZK proof for */
	blocks: BlockWithPlaintext[]
	/** params for ZK proof gen */
	operator?: ZKOperator
	/** redact selected portions of the plaintext */
	redact: (plaintext: Uint8Array) => ArraySlice[]
	logger?: Logger
}

type ZKVerifyOpts = {
	ciphertext: Uint8Array
	// eslint-disable-next-line camelcase
	zkReveal: FinaliseSessionRequest_BlockRevealZk
	operator: ZKOperator
	logger?: Logger
}

let zkOperator: Promise<ZKOperator> | undefined
export function makeDefaultZkOperator(logger?: Logger) {
	if(!zkOperator) {
		const isNode = detectEnvironment() === 'node'
		logger?.debug(
			{ type: isNode ? 'local' : 'remote' },
			'using zk operator'
		)

		zkOperator = isNode
			? makeLocalSnarkJsZkOperator(logger)
			: makeRemoteSnarkJsZkOperator(logger)
	}

	return zkOperator
}

/**
 * Generate ZK proofs for the given blocks with a redaction function.
 */
export async function prepareZkProofs(
	{
		blocks,
		operator,
		redact,
		logger
	}: PrepareZKProofsOpts
) {
	const blocksToReveal = getBlocksToReveal(blocks, redact)
	if(blocksToReveal === 'all') {
		return 'all'
	}

	logger = logger || LOGGER.child({ module: 'zk' })
	operator = operator || await makeDefaultZkOperator(logger)
	logger.info(
		{ len: blocksToReveal.length },
		'preparing proofs for blocks'
	)

	let totalChunks = 0
	const zkBlocks = blocksToReveal.map((block): ZKBlock => {
		const chunks = getBlockWithIvCounter(block.redactedPlaintext)
		totalChunks += chunks.length
		return {
			block: block.block,
			zkChunks: chunks,
			redactedPlaintext: block.redactedPlaintext
		}
	})

	if(totalChunks > MAX_ZK_CHUNKS) {
		throw new Error(
			`Too many chunks to prove: ${totalChunks} > ${MAX_ZK_CHUNKS}`
		)
	}

	logger.info({ totalChunks }, 'extracted chunks')

	await Promise.all(
		zkBlocks.map(async({ block, zkChunks }) => {
			block.zkReveal = {
				proofs: await Promise.all(
					zkChunks.map(async({ chunk, counter }) => {
						const startIdx = (counter - 1) * CHACHA_BLOCK_SIZE
						const endIdx = counter * CHACHA_BLOCK_SIZE
						const ciphertextChunk = block.ciphertext.slice(
							startIdx,
							endIdx
						)

						const proof = await generateProof(
							{
								key: block.directReveal!.key,
								iv: block.directReveal!.iv,
								startCounter: counter,
							},
							{
								ciphertext: ciphertextChunk
							},
							operator!,
						)

						logger?.debug(
							{ startIdx, endIdx },
							'generated proof for chunk'
						)
						return {
							proofJson: proof.proofJson,
							decryptedRedactedCiphertext: toUint8Array(
								proof.plaintext
							),
							redactedPlaintext: chunk,
							startIdx,
						}
					})
				)
			}

			delete block.directReveal

			return block
		})
	)

	return zkBlocks
}


/**
 * Verify the given ZK proof
 */
export async function verifyZKBlock(
	{
		ciphertext,
		zkReveal,
		operator,
		logger
	}: ZKVerifyOpts,
) {
	if(!zkReveal) {
		throw new Error('No ZK reveal')
	}

	const { proofs } = zkReveal
	/**
	 * to verify if the user has given us the correct redacted plaintext,
	 * and isn't providing plaintext that they haven't proven they have
	 * we start with a fully redacted plaintext, and then replace the
	 * redacted parts with the plaintext that the user has provided
	 * in the proofs
	 */
	const realRedactedPlaintext = new Uint8Array(
		ciphertext.length,
	).fill(REDACTION_CHAR_CODE)


	await Promise.all(
		proofs.map(async({
			proofJson,
			decryptedRedactedCiphertext,
			redactedPlaintext,
			startIdx,
		}, i) => {
			// get the ciphertext chunk we received from the server
			// the ZK library, will verify that the decrypted redacted
			// ciphertext matches the ciphertext received from the server
			const ciphertextChunk = ciphertext.slice(
				startIdx,
				startIdx + redactedPlaintext.length
			)

			if(!isRedactionCongruent(
				redactedPlaintext,
				decryptedRedactedCiphertext
			)) {
				throw new Error(`redacted ciphertext (${i}) not congruent`)
			}

			await verifyProof(

				{
					proofJson,
					plaintext:
						toUintArray(decryptedRedactedCiphertext),
				}
				,
				{
					ciphertext: ciphertextChunk,
				},
				operator
			)

			logger?.debug(
				{ startIdx, endIdx: startIdx + redactedPlaintext.length },
				'verified proof'
			)

			realRedactedPlaintext.set(
				redactedPlaintext,
				startIdx,
			)
		})
	)

	return {
		redactedPlaintext: realRedactedPlaintext,
	}
}


/**
 * Split the redacted plaintext into chacha-sized chunks,
 * and set a counter for each chunk.
 *
 * It will only return blocks that are fully or partially revealed
 * @param redactedPlaintext the redacted plaintext that need be split
 * @param blockSize the size of blocks to split data into
 */
function getBlockWithIvCounter(
	redactedPlaintext: Uint8Array,
	blockSize = CHACHA_BLOCK_SIZE
) {
	const chunks = chunkBuffer(redactedPlaintext, blockSize)
	const chunksWithCounter: ZKChunk[] = []
	for(let i = 0;i < chunks.length;i++) {
		if(!isFullyRedacted(chunks[i])) {
			chunksWithCounter.push({
				chunk: chunks[i],
				counter: i + 1,
			})
		}
	}

	return chunksWithCounter
}

function chunkBuffer(buffer: Uint8Array, chunkSize: number) {
	const chunks: Uint8Array[] = []
	for(let i = 0;i < buffer.length;i += chunkSize) {
		chunks.push(buffer.slice(i, i + chunkSize))
	}

	return chunks
}
