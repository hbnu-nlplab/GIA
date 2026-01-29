import { useState } from 'react'
import { useAppStore } from '../store'

export default function EvidencePanel({ onClose }: { onClose: () => void }) {
  const { evidenceList, clearEvidence, openDetail } = useAppStore(state => ({
    evidenceList: state.evidenceList,
    clearEvidence: state.clearEvidence,
    openDetail: state.openDetail
  }))

  const [isCollapsed, setIsCollapsed] = useState(false)

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'text-emerald-500'
      case 'warning': return 'text-amber-500'
      case 'error': return 'text-rose-500'
      default: return 'text-muted-foreground'
    }
  }

  return (
    <div className={`bg-card/95 backdrop-blur-xl border border-border rounded-xl shadow-2xl overflow-hidden flex flex-col transition-all duration-300 ${isCollapsed ? 'h-auto' : 'h-full max-h-[600px]'} animate-in fade-in zoom-in duration-200`}>
      <div className="px-4 py-3 border-b border-border flex items-center justify-between bg-muted/20 cursor-pointer hover:bg-muted/30 transition-colors" onClick={() => setIsCollapsed(!isCollapsed)}>
        <div className="flex items-center gap-2">
          <span className="text-xs">{isCollapsed ? '▶' : '▼'}</span>
          <span className="text-xs">📊</span>
          <h3 className="text-[11px] font-bold uppercase tracking-[0.1em] text-muted-foreground">
            Verification Stack
          </h3>
          {evidenceList.length > 0 && (
            <span className="bg-primary/20 text-primary text-[9px] px-1.5 py-0.5 rounded-full font-bold">
              {evidenceList.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {!isCollapsed && evidenceList.length > 0 && (
            <button 
              onClick={(e) => { e.stopPropagation(); clearEvidence(); }}
              className="text-[10px] text-muted-foreground hover:text-rose-500 transition-colors px-2 py-1"
            >
              Clear
            </button>
          )}
          <button onClick={(e) => { e.stopPropagation(); onClose(); }} className="text-muted-foreground hover:text-foreground transition-colors p-1">
            <span className="text-xs">✕</span>
          </button>
        </div>
      </div>

      {!isCollapsed && (
        <>
          <div className="overflow-y-auto p-3 space-y-2 min-h-[100px]">
            {evidenceList.length === 0 ? (
              <div className="py-8 flex flex-col items-center justify-center opacity-30 select-none">
                <div className="text-2xl mb-2">🔍</div>
                <p className="text-[10px] font-bold uppercase tracking-widest text-center">No evidence collected</p>
              </div>
            ) : (
              evidenceList.map(item => (
                <div
                  key={item.id}
                  onClick={() => openDetail('evidence', item.id)}
                  className="p-3 rounded-lg bg-muted/40 border border-border/50 hover:border-primary/40 hover:bg-muted/70 transition-all cursor-pointer group animate-in slide-in-from-right-4 duration-300"
                >
                  <div className="flex items-start justify-between mb-1.5">
                    <span className={`text-[10px] font-black uppercase tracking-tighter ${getStatusColor(item.status)}`}>
                      {item.status}
                    </span>
                    <span className="text-[9px] text-muted-foreground/50 font-mono">{item.timestamp}</span>
                  </div>
                  <div className="text-[13px] font-semibold text-foreground mb-0.5 group-hover:text-primary transition-colors leading-tight">
                    {item.title}
                  </div>
                  <div className="text-[11px] text-muted-foreground/80 line-clamp-2 leading-snug">
                    {item.summary}
                  </div>
                </div>
              ))
            )}
          </div>
          
          {evidenceList.length > 0 && (
            <div className="p-3 bg-muted/20 border-t border-border">
              <p className="text-[9px] text-center text-muted-foreground/40 font-medium uppercase tracking-widest mb-2">
                Click cards to inspect raw tool output
              </p>
            </div>
          )}
        </>
      )}
    </div>
  )
}

