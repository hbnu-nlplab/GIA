import { useState } from 'react'
import SettingsDialog from './SettingsDialog'
import { useAppStore } from '../store'

export default function Header() {
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isPreparing, setIsPreparing] = useState(false)
  const [prepareStatus, setPrepareStatus] = useState<string | null>(null)
  const [isSettingsOpen, setIsSettingsOpen] = useState(false)
  const settings = useAppStore(state => state.settings)
  const addEvidence = useAppStore(state => state.addEvidence)
  const setLabPrepare = useAppStore(state => state.setLabPrepare)
  const setLabRefreshResult = useAppStore(state => state.setLabRefreshResult)

  const handleRefresh = async () => {
    setIsRefreshing(true)
    try {
      const overrides: Record<string, string> = {}
      if (settings.oobIntf) overrides.PNETLAB_OOB_INTF = settings.oobIntf
      if (settings.deviceGroup) overrides.PNETLAB_DEVICE_GROUP = settings.deviceGroup
      if (settings.pnetlabVmIp) overrides.PNETLAB_VM_IP = settings.pnetlabVmIp
      if (settings.gatewayIp) overrides.PNETLAB_GATEWAY_IP = settings.gatewayIp
      if (settings.nsoAuthgroup) overrides.NSO_AUTHGROUP = settings.nsoAuthgroup
      if (settings.nsoNedId) overrides.NSO_NED_ID = settings.nsoNedId

      const res = await fetch('/api/lab/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ overrides })
      })
      const data = await res.json()
      setLabRefreshResult(data)
      addEvidence({
        type: 'lab_refresh',
        status: res.ok ? 'success' : 'error',
        title: res.ok ? 'Lab Refresh Complete' : 'Lab Refresh Failed',
        summary: res.ok ? `New devices: ${data?.missing?.length || 0}` : (data?.detail || 'Error'),
        details: data
      })
    } catch {
      // best-effort refresh for demo
    } finally {
      setIsRefreshing(false)
    }
  }

  const handlePrepare = async () => {
    setIsPreparing(true)
    try {
      const res = await fetch('/api/lab/prepare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auto_init_batfish: false })
      })
      const data = await res.json()
      setLabPrepare(data?.status || (res.ok ? 'ready' : 'error'), data)
      setPrepareStatus(data?.status || (res.ok ? 'ready' : 'error'))
      addEvidence({
        type: 'lab_prepare',
        status: res.ok ? 'success' : 'error',
        title: res.ok ? 'Batfish Prepare' : 'Batfish Prepare Failed',
        summary: res.ok ? `Status: ${data?.status}` : (data?.detail || 'Error'),
        details: data
      })
    } catch {
      setPrepareStatus('error')
    } finally {
      setIsPreparing(false)
    }
  }

  const statusColor = (status: string | null) => {
    if (!status) return 'bg-emerald-500'
    if (status === 'ready' || status === 'loaded' || status === 'initialized') return 'bg-emerald-500'
    if (status === 'not_ready') return 'bg-amber-500'
    return 'bg-red-500'
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
              <div className={`w-1.5 h-1.5 rounded-full ${statusColor(prepareStatus)} animate-pulse`} />
              <span className="text-foreground/80">
                Batfish: {prepareStatus || 'unknown'}
              </span>
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
            <button
              onClick={handlePrepare}
              disabled={isPreparing}
              className={`h-7 px-3 text-[10px] font-black uppercase tracking-widest bg-primary text-primary-foreground shadow-lg rounded-md transition-all hover:scale-105 active:scale-95 ${isPreparing ? 'animate-pulse opacity-70' : ''}`}
            >
              {isPreparing ? 'Preparing...' : 'Prepare'}
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
