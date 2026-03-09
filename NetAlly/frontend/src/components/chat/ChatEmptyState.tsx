import { Sparkles } from 'lucide-react'
import { SUGGESTIONS } from './types'

interface ChatEmptyStateProps {
  onSuggestionClick: (text: string) => void
}

export default function ChatEmptyState({ onSuggestionClick }: ChatEmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[360px] gap-6 px-4">
      <div className="flex flex-col items-center gap-3">
        <div className="w-11 h-11 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
          <Sparkles className="w-5 h-5 text-primary" />
        </div>
        <div className="text-center">
          <h3 className="text-base font-semibold text-foreground">NetAlly Copilot</h3>
          <p className="text-sm text-muted-foreground mt-1">
            Ask anything about your network topology
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2 w-full max-w-xs">
        {SUGGESTIONS.map((s, i) => (
          <button
            key={i}
            type="button"
            onClick={() => onSuggestionClick(s)}
            className="text-left px-4 py-3 rounded-xl border border-border hover:border-primary/30 hover:bg-primary/5 text-sm text-foreground/80 transition-all group"
          >
            <span className="text-muted-foreground group-hover:text-primary transition-colors mr-1.5">&rarr;</span>
            {s}
          </button>
        ))}
      </div>
    </div>
  )
}
