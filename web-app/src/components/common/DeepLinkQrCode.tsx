import { QRCodeSVG } from 'qrcode.react'

interface DeepLinkQrCodeProps {
	value: string
}

export function DeepLinkQrCode({ value }: DeepLinkQrCodeProps) {
	return (
		<div className="rounded-lg border bg-card p-3 flex flex-col items-center gap-2">
			<QRCodeSVG
				value={value}
				size={176}
				marginSize={2}
				bgColor="transparent"
				fgColor="currentColor"
				level="M"
			/>
			<p className="text-xs text-muted-foreground text-center">
				Scan to open receive page with ticket
			</p>
		</div>
	)
}

export default DeepLinkQrCode
