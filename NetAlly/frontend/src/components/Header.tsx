import { useState } from 'react'
import SettingsDialog from './SettingsDialog'

export default function Header() {
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isSettingsOpen, setIsSettingsOpen] = useState(false)

  const handleRefresh = async () => {
    setIsRefreshing(true)
    await new Promise(r => setTimeout(r, 1000))
    window.location.reload()
    setIsRefreshing(false)
  }

  return (
    <>
      <header className="h-12 border-b border-border bg-background/80 backdrop-blur-xl px-6 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2.5 group cursor-pointer" onClick={() => window.location.reload()}>
            <div className="w-6 h-6 bg-primary rounded-md flex items-center justify-center group-hover:scale-110 transition-transform">
              <span className="text-xs text-primary-foreground font-black tracking-tighter">NA</span>
            </div>
            <span className="font-bold text-sm tracking-tighter uppercase italic">NetAlly</span>
          </div>
          
          <nav className="flex items-center gap-4 text-[11px] font-bold border-l border-border/50 pl-6 select-none uppercase tracking-widest">
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground/60">Lab:</span>
              <span className="text-foreground border-b border-primary/40 pb-0.5">SP-Core-V5</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground/60">Snapshot:</span>
              <span className="text-foreground">01.29 / 18:24</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-emerald-500/80">Active</span>
            </div>
          </nav>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1 bg-muted/30 p-1 rounded-lg border border-border/40">
            <button 
              onClick={handleRefresh}
              disabled={isRefreshing}
              className={`h-7 px-3 text-[10px] font-black uppercase tracking-widest text-muted-foreground hover:text-foreground hover:bg-card/50 rounded-md transition-all ${isRefreshing ? 'animate-pulse opacity-50' : ''}`}
            >
              {isRefreshing ? 'Syncing...' : 'Refresh'}
            </button>
            <button className="h-7 px-3 text-[10px] font-black uppercase tracking-widest bg-primary text-primary-foreground shadow-lg rounded-md transition-all hover:scale-105 active:scale-95">
              Health Check
            </button>
          </div>
          
          <div className="w-px h-4 bg-border/50" />
          
          <div className="flex items-center gap-3">
            <button 
              onClick={() => setIsSettingsOpen(true)}
              className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
              title="System Settings"
            >
              <span className="text-lg">⚙️</span>
            </button>
            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-emerald-600 to-sky-600 border border-primary/20 shadow-xl" />
          </div>
        </div>
      </header>

      <SettingsDialog isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)} />
    </>
  )
}

