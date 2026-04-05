const SENDME_SCHEME = 'sendme'
const MAX_TICKET_LENGTH = 512

export interface DeepLinkPayload {
	action: string
	ticket?: string | null
}

export function parseDeepLinkUrl(value: string): DeepLinkPayload | null {
	if (!value.trim()) return null

	let parsed: URL
	try {
		parsed = new URL(value.trim())
	} catch {
		return null
	}

	if (parsed.protocol !== `${SENDME_SCHEME}:`) return null

	const action = parsed.hostname?.toLowerCase()
	if (!action) return null
	if (action !== 'send' && action !== 'receive') return null

	return {
		action,
		ticket: parsed.searchParams.get('ticket'),
	}
}

function sanitizeTicket(ticket: string | null | undefined): string | null {
	if (!ticket) return null
	const trimmed = ticket.trim()
	if (!trimmed) return null
	if (trimmed.length > MAX_TICKET_LENGTH) return null
	for (let index = 0; index < trimmed.length; index += 1) {
		const codePoint = trimmed.charCodeAt(index)
		if (codePoint <= 0x1f || codePoint === 0x7f) return null
	}
	return trimmed
}

export function buildReceiveDeepLink(ticket: string): string {
	const safeTicket = sanitizeTicket(ticket)
	if (!safeTicket) return `${SENDME_SCHEME}://receive`
	return `${SENDME_SCHEME}://receive?ticket=${encodeURIComponent(safeTicket)}`
}

export function routeFromPayload(payload: DeepLinkPayload): string | null {
	const action = payload.action?.toLowerCase()
	if (action === 'send') return '/?tab=send'
	if (action === 'receive') {
		const safeTicket = sanitizeTicket(payload.ticket)
		if (safeTicket) {
			return `/?tab=receive&ticket=${encodeURIComponent(safeTicket)}`
		}
		return '/?tab=receive'
	}
	return null
}
