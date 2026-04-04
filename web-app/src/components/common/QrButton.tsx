import { useRef } from 'react'
import { QRCodeCanvas } from 'qrcode.react'
import { QrCode } from 'lucide-react'
import { Popover, PopoverTrigger, PopoverPopup } from '../ui/popover'
import { useTranslation } from '../../i18n/react-i18next-compat'
import { toastManager } from '../ui/toast'
import { buttonVariants } from '../ui/button'
import { writeImage } from '@tauri-apps/plugin-clipboard-manager'
import { Image } from '@tauri-apps/api/image'

interface QrButtonProps {
	value: string
}

export default function QrButton({ value }: QrButtonProps) {
	const { t } = useTranslation()
	const canvasRef = useRef<HTMLCanvasElement | null>(null)

	const copyQrCode = async () => {
		if (!canvasRef.current) return

		try {
			const canvas = canvasRef.current
			const ctx = canvas.getContext('2d', { willReadFrequently: true })
			if (!ctx) {
				throw new Error('Failed to read QR code pixels')
			}
			const { data, width, height } = ctx.getImageData(
				0,
				0,
				canvas.width,
				canvas.height
			)
			const image = await Image.new(new Uint8Array(data), width, height)
			await writeImage(image)
			await image.close()

			const toastId = crypto.randomUUID()
			toastManager.add({
				title: t('common:copied'),
				type: 'success',
				id: toastId,
			})
			setTimeout(() => {
				toastManager.close(toastId)
			}, 2000)
		} catch (e) {
			console.error('Failed to copy QR code to clipboard:', e)
			const errorMsg =
				e instanceof Error
					? `${t('common:errors.copyFailed')}: ${e.message}`
					: t('common:errors.copyFailed')
			toastManager.add({
				title: errorMsg,
				type: 'error',
				id: crypto.randomUUID(),
			})
		}
	}

	return (
		<Popover>
			<PopoverTrigger
				className={buttonVariants({ variant: 'outline', size: 'icon-xs' })}
				title={t('common:sender.showQrCode')}
			>
				<QrCode className="h-4 w-4" />
			</PopoverTrigger>
			<PopoverPopup side="top" align="center" className="w-fit">
				<button
					type="button"
					className="group flex flex-col items-center gap-3 outline-none"
					onClick={copyQrCode}
					aria-label={t('common:sender.qrCodeClickToCopy')}
					title={t('common:sender.qrCodeClickToCopy')}
				>
					<QRCodeCanvas
						value={value}
						ref={canvasRef}
						size={176}
						marginSize={2}
						bgColor="#ffffff"
						fgColor="currentColor"
						level="M"
						className="cursor-pointer transition-transform duration-200 group-hover:scale-105"
					/>
					<p className="text-center text-xs text-muted-foreground">
						{t('common:sender.qrCodeClickToCopy')}
					</p>
				</button>
			</PopoverPopup>
		</Popover>
	)
}
