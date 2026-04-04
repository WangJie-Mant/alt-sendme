const SENDME_SCHEME = 'sendme'
const MAX_TICKET_LENGTH = 512

export interface DeepLinkPayload {
	action: string
	ticket?: string | null
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
