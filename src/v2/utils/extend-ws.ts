/**
 * This file extends the WebSocket class with
 * additional methods and properties to aid with
 * the Reclaim's RPC communication.
 *
 * These functions can be used on the client & server
 * side to send and receive RPC messages.
 */
import { strToUint8Array } from '@reclaimprotocol/tls'
import { ReclaimRPCMessage } from '../../proto/api'
import { WitnessError } from '../../utils'
import { REQUEST_RESPONSE_MATCHES, RPCEvent, RPCRequestType, RPCResponseData } from '../types'
import { generateRpcMessageId, makeRpcEvent } from './generics'
import EventEmitter from 'events'

if(typeof WebSocket !== 'undefined') {
	// extend the WebSocket prototype
	extendWsPrototype(WebSocket)
}

export async function extendWsPrototype(WS: typeof WebSocket) {
	WS.prototype.sendMessage = async function(msg) {
		if(this.readyState !== WebSocket.OPEN) {
			throw new Error('socket is not open')
		}

		msg.id ||= generateRpcMessageId()
		const bytes = ReclaimRPCMessage
			.encode(ReclaimRPCMessage.create(msg))
			.finish()
		await this.send(bytes)
	}

	WS.prototype.terminateConnection = async function(err) {
		// connection already closed
		if(this.readyState === WebSocket.CLOSED) {
			return
		}

		try {
			const witErr = err
				? WitnessError.fromError(err)
				: new WitnessError('WITNESS_ERROR_NO_ERROR', '')
			this.dispatchRPCEvent('connection-terminated', witErr)
			if(this.readyState === this.OPEN) {
				await this.sendMessage({
					connectionTerminationAlert: witErr.toProto()
				})
			}
		} catch(err) {
			this.logger?.error({ err }, 'error terminating connection')
		} finally {
			this.close()
		}
	}

	WS.prototype.startProcessingRpcMessages = function() {
		this.addEventListener('error', (event: ErrorEvent) => {
			const witErr = WitnessError.fromError(
				event.error
					|| new Error(event.message)
			)
			this.dispatchRPCEvent('connection-terminated', witErr)
		})

		this.addEventListener('close', () => (
			this.dispatchRPCEvent(
				'connection-terminated',
				new WitnessError(
					'WITNESS_ERROR_NO_ERROR',
					'connection closed'
				)
			)
		))


		this.addEventListener('message', ({ data }) => {
			try {
				messageHandler.call(this, data)
			} catch(err) {
				this.logger?.error({ err }, 'error processing message')
				this.terminateConnection(err)
			}
		})

		function messageHandler(this: WebSocket, data: unknown) {
			// extract array buffer from WS data & decode proto
			const buff = extractArrayBufferFromWsData(data)
			const msg = ReclaimRPCMessage.decode(new Uint8Array(buff))
			// handle connection termination alert
			if(msg.connectionTerminationAlert?.code) {
				const err = WitnessError.fromProto(
					msg.connectionTerminationAlert
				)
				this.logger?.warn(
					{ err },
					'received connection termination alert'
				)
				this.dispatchRPCEvent('connection-terminated', err)
				return
			}

			if(msg.initResponse) {
				this.initialised = true
				this.dispatchRPCEvent('init-response', {})
				return
			}

			const rpcRequest = getRpcRequest(msg)
			if(rpcRequest) {
				if(
					rpcRequest.direction === 'response'
					&& rpcRequest.type === 'error'
				) {
					this.dispatchRPCEvent('rpc-response', {
						id: msg.id,
						error: WitnessError.fromProto(msg.requestError!)
					})
					return
				}

				const resType = REQUEST_RESPONSE_MATCHES[rpcRequest.type]
					.response.type

				if(rpcRequest.direction === 'response') {
					this.dispatchRPCEvent('rpc-response', {
						id: msg.id,
						type: rpcRequest.type,
						data: msg[resType]!
					})
					return
				}

				this.dispatchRPCEvent('rpc-request', {
					type: rpcRequest.type,
					data: msg[rpcRequest.type]!,
					respond: (res) => {
						if('code' in res) {
							return this.sendMessage({
								id: msg.id,
								requestError: res.toProto()
							})
						}

						return this
							.sendMessage({ id: msg.id, [resType]: res })
					},
				})
				return
			}

			if(msg.tlsMessage) {
				this.dispatchRPCEvent('tls-message', msg.tlsMessage)
				return
			}

			throw new WitnessError(
				'WITNESS_ERROR_INTERNAL',
				'unknown message type',
				{ msg }
			)
		}
	}

	WS.prototype.dispatchRPCEvent = function(
		this: WebSocket | EventEmitter,
		type,
		data
	) {
		const event = makeRpcEvent(type, data)
		if('dispatchEvent' in this) {
			this.dispatchEvent(event)
			return
		}

		this.emit(type, event)
	}

	WS.prototype.rpc = async function(type, request) {
		const id = generateRpcMessageId()
		// setup a promise to wait for the response
		const promise = new Promise<RPCResponseData<typeof type>>((resolve, reject) => {
			const handler = (event: RPCEvent<'rpc-response'>) => {
				if(event.data.id !== id) {
					return
				}

				this.removeEventListener('rpc-response', handler)
				if('error' in event.data) {
					reject(event.data.error)
					return
				}

				// check if the response type matches the request type
				// if not, reject the promise
				if(event.data.type !== type) {
					reject(
						new Error(
							'unexpected response type: '
								+ event.data.type
						)
					)
					return
				}

				resolve(event.data.data as RPCResponseData<typeof type>)
			}

			this.addEventListener('rpc-response', handler)
		})

		await this.sendMessage({ id, [type]: request })

		return await promise
	}

	WS.prototype.waitForInit = async function() {
		if(this.initialised) {
			return
		}

		if(this.readyState === WebSocket.CLOSED) {
			throw new Error('socket is closed')
		}

		await new Promise<void>((resolve, reject) => {
			const handler = () => {
				removeHandlers()
				resolve()
			}

			const rejectHandler = (event: RPCEvent<'connection-terminated'>) => {
				removeHandlers()
				reject(event.data)
			}

			const removeHandlers = () => {
				this.removeEventListener('init-response', handler)
				this.removeEventListener('connection-terminated', rejectHandler)
			}

			this.addEventListener('init-response', handler)
			this.addEventListener('connection-terminated', rejectHandler)
		})
	}
}

function extractArrayBufferFromWsData(data: unknown): ArrayBuffer {
	if(data instanceof ArrayBuffer) {
		return data
	}

	// uint8array/Buffer
	if(typeof data === 'object' && data && 'buffer' in data) {
		return data.buffer as ArrayBuffer
	}

	if(typeof data === 'string') {
		return strToUint8Array(data).buffer
	}

	throw new Error('unsupported data: ' + String(data))
}

function getRpcRequest(msg: ReclaimRPCMessage) {
	if(msg.requestError) {
		return {
			direction: 'response' as const,
			type: 'error' as const
		}
	}

	for(const key in msg) {
		if(REQUEST_RESPONSE_MATCHES[key]) {
			return {
				direction: 'request' as const,
				type: key as RPCRequestType
			}
		}

		for(const [reqKey, value] of Object.entries(REQUEST_RESPONSE_MATCHES)) {
			if(value.response.type === key) {
				return {
					direction: 'response' as const,
					type: reqKey as RPCRequestType
				}
			}
		}
	}
}