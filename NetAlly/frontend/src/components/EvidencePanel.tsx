import { useAppStore } from '../store'
import { ClipboardCheck, Trash2, X } from 'lucide-react'

export default function EvidencePanel({ onClose }: { onClose: () => void }) {
  const { evidenceList, clearEvidence, openDetail } = useAppStore(state => ({
    evidenceList: state.evidenceList,
    clearEvidence: state.clearEvidence,
    openDetail: state.openDetail
  }))

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'text-emerald-500'
      case 'warning': return 'text-amber-500'
      case 'error': return 'text-rose-500'
      default: return 'text-muted-foreground'
    }
  }

  const getStatusDot = (status: string) => {
    switch (status) {
      case 'success': return 'bg-emerald-500'
      case 'warning': return 'bg-amber-500'
      case 'error': return 'bg-rose-500'
      default: return 'bg-muted-foreground'
    }
  }

  return (
    <div className="h-full flex flex-col bg-card border-l border-border-subtle shadow-elevation-3">
      {/* Header */}
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ClipboardCheck className="w-3.5 h-3.5 text-primary" />
          <h3 className="text-ui-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Verification Stack
          </h3>
          {evidenceList.length > 0 && (
            <span className="text-ui-xs px-1.5 py-0.5 rounded bg-primary/15 text-primary font-semibold">
              {evidenceList.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {evidenceList.length > 0 && (
            <button
              onClick={clearEvidence}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-rose-500 hover:bg-rose-500/10 transition-colors"
              title="Clear all evidence"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Evidence list */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {evidenceList.length === 0 ? (
          <div className="py-12 flex flex-col items-center justify-center gap-2">
            <ClipboardCheck className="w-6 h-6 text-muted-foreground/30" />
            <p className="text-ui-xs text-muted-foreground/50">No evidence collected</p>
          </div>
        ) : (
          evidenceList.map(item => (
            <button
              key={item.id}
              type="button"
              onClick={() => openDetail('evidence', item.id)}
              className="w-full text-left p-3 rounded-lg bg-muted/30 border border-border/50 hover:border-primary/30 hover:bg-muted/50 transition-all"
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-1.5">
                  <span className={`w-1.5 h-1.5 rounded-full ${getStatusDot(item.status)}`} />
                  <span className={`text-ui-xs font-semibold uppercase ${getStatusColor(item.status)}`}>
                    {item.status}
                  </span>
                </div>
                <span className="text-ui-xs text-muted-foreground/50 font-mono">{item.timestamp}</span>
              </div>
              <div className="text-ui-sm font-semibold text-foreground mb-0.5 leading-tight">
                {item.title}
              </div>
              <div className="text-ui-xs text-muted-foreground/80 line-clamp-2 leading-snug">
                {item.summary}
              </div>
            </button>
          ))
        )}
      </div>

      {/* Footer hint */}
      {evidenceList.length > 0 && (
        <div className="px-3 py-2 border-t border-border">
          <p className="text-ui-xs text-center text-muted-foreground/40">
            Click cards to inspect raw tool output
          </p>
        </div>
      )}
    </div>
  )
}
