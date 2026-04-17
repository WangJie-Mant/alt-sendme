import { Share2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from '../../i18n/react-i18next-compat'
import type { ShareActionProps } from '../../types/sender'
import { Button } from '../ui/button'
import { Input } from '../ui/input'

export function ShareActionCard({
	selectedPaths,
	selectedPath,
	isLoading,
	onStartSharing,
}: ShareActionProps & { onStartSharing: (phrase?: string) => Promise<void> }) {
	const { t } = useTranslation()
	const [phrase, setPhrase] = useState('')
	if (!selectedPaths.length && !selectedPath) return null

	return (
		<div className="space-y-4">
			<div className="space-y-2">
				<p className="text-sm text-muted-foreground">Optional phrase sharing</p>
				<Input
					type="text"
					value={phrase}
					onChange={(e) => setPhrase(e.target.value)}
					placeholder="Input a phrase to share without sending ticket"
					disabled={isLoading}
				/>
			</div>
			<Button
				type="button"
				onClick={() => onStartSharing(phrase.trim() || undefined)}
				disabled={isLoading}
				className="w-full"
			>
				<Share2 className="h-4 w-4 mr-2" />
				{isLoading
					? t('common:sender.startingShare')
					: t('common:sender.startSharing')}
			</Button>
		</div>
	)
}
