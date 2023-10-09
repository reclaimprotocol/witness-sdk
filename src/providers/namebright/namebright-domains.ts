
import { DEFAULT_PORT } from '../../config'
import { Provider } from '../../types'
import { uint8ArrayToStr } from '../../utils'
import { getCompleteHttpResponseFromReceipt, getHttpRequestHeadersFromTranscript } from '../../utils/http-parser'


// params for the request that will be publicly available
// contains the domain list of the logged in user
type NameBrightDomains = {
	domainList: string

}

// params required to generate the http request to NameBright
// these would contain fields that are to be hidden from the public,
// including the witness
type NameBrightSecretParams = {
	/** bearer token for authentication */
	authorisationHeader: string
}

// where to send the HTTP request
const HOST = 'client.namebright.com'
const HOSTPORT = `${HOST}:${DEFAULT_PORT}`


// what API to call
const METHOD = 'POST'
const PATH = '/SearchDomains'

const nameBrightDomainList: Provider<NameBrightDomains, NameBrightSecretParams> = {
	hostPort: HOSTPORT,
	areValidParams(params): params is NameBrightDomains {
		return (
			typeof params.domainList === 'string'
		)
	},
	createRequest({ authorisationHeader }) {
		// this is a simple http request construction.
		// see https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
		const bodyVal = JSON.stringify({
			sortBy:'domainName',
			sortDirection:'Ascending'
		})
		const data = [
			`${METHOD} ${PATH} HTTP/1.1`,
			'Host: ' + HOST,
			'accept: application/json, text/plain, */*',
			'accept-language: en-GB,en-US;q=0.9,en;q=0.8',
			'authorization: ' + authorisationHeader,
			'Connection: close',
			'content-length: ' + bodyVal.length,
			'content-type: application/json',
			`\r\n${bodyVal}`
		].join('\r\n')

		// find the cookie string and redact it
		const tokenStartIndex = data.indexOf(authorisationHeader)

		return {
			data,
			// anything that should be redacted from the transcript
			// should be added to this array
			redactions: [
				{
					fromIndex: tokenStartIndex,
					toIndex: tokenStartIndex + authorisationHeader.length
				}
			]
		}
	},
	assertValidProviderReceipt(receipt, { domainList }) {
		// ensure the request was sent to the right place
		if(receipt.hostPort !== HOSTPORT) {
			throw new Error(`Invalid hostPort: ${receipt.hostPort}`)
		}

		// parse the HTTP request & check
		// the method, URL, headers, etc. match what we expect
		const req = getHttpRequestHeadersFromTranscript(receipt)
		if(req.method !== METHOD.toLowerCase()) {
			throw new Error(`Invalid method: ${req.method}`)
		}

		if(!req.url.startsWith(PATH)) {
			throw new Error(`Invalid path: ${req.url}`)
		}

		// we ensure the connection header was sent as "close"
		// this is done to avoid any possible malicious request
		// that contains multiple requests, but via redactions
		// is spoofed as a single request
		if(req.headers['connection'] !== 'close') {
			throw new Error('Invalid connection header')
		}

		if(!req.url.startsWith(PATH)) {
			throw new Error(`Invalid path: ${req.url}`)
		}

		const res = getCompleteHttpResponseFromReceipt(
			receipt
		)

		if(res.statusCode !== 200) {
			throw new Error(`Invalid status code: ${res.statusCode}`)
		}

		if(!res.headers['content-type']?.startsWith('application/json')) {
			throw new Error(`Invalid content-type: ${res.headers['content-type']}`)
		}

		try {
			const resBody = JSON.parse(uint8ArrayToStr(res.body))
			if(resBody?.result.items.length && domainList === '') {
				throw new Error(`Received Domain list does not match expected "${domainList}"`)
			}

			let extractedDomains = ''
			if(resBody?.result.items.length) {
				console.log(resBody?.result.items)
				for(var i = 0;i < resBody?.result.items.length;i++) {
					extractedDomains += (resBody?.result.items[i].domainName) + ','
				}
			}

			if(extractedDomains !== domainList) {
				throw new Error(`Received Domain list ${extractedDomains} does not match expected "${domainList}"`)
			}
		} catch(error) {
			throw new Error(error)
		}
	},
}

export default nameBrightDomainList


