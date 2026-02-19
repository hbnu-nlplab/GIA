import { useEffect, useRef, useState } from 'react'
import SettingsDialog from './SettingsDialog'
import { useAppStore } from '../store'

const LONG_TASK_TIMEOUT_MS = 30_000

export default function Header() {
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isPreparing, setIsPreparing] = useState(false)
  const [prepareStatus, setPrepareStatus] = useState<string | null>(null)
  const [isSettingsOpen, setIsSettingsOpen] = useState(false)
  const [refreshError, setRefreshError] = useState<string | null>(null)
  const [prepareError, setPrepareError] = useState<string | null>(null)
  const [lastRefreshOverrides, setLastRefreshOverrides] = useState<Record<string, string> | null>(null)
  const [lastPrepareAutoInit, setLastPrepareAutoInit] = useState<boolean>(false)
  const [showRefreshLog, setShowRefreshLog] = useState(false)
  const refreshAbortRef = useRef<AbortController | null>(null)
  const prepareAbortRef = useRef<AbortController | null>(null)
  const refreshTimerRef = useRef<number | null>(null)
  const prepareTimerRef = useRef<number | null>(null)
  const settings = useAppStore(state => state.settings)
  const addEvidence = useAppStore(state => state.addEvidence)
  const setLabPrepare = useAppStore(state => state.setLabPrepare)
  const setLabRefreshResult = useAppStore(state => state.setLabRefreshResult)
  const labRefreshResult = useAppStore(state => state.labRefreshResult)
  const runtimeHealth = useAppStore(state => state.runtimeHealth)
  const setRuntimeHealth = useAppStore(state => state.setRuntimeHealth)

  const clearTaskTimer = (kind: 'refresh' | 'prepare') => {
    if (kind === 'refresh' && refreshTimerRef.current !== null) {
      window.clearTimeout(refreshTimerRef.current)
      refreshTimerRef.current = null
    }
    if (kind === 'prepare' && prepareTimerRef.current !== null) {
      window.clearTimeout(prepareTimerRef.current)
      prepareTimerRef.current = null
    }
  }

  const startTaskTimeout = (kind: 'refresh' | 'prepare', controller: AbortController) => {
    clearTaskTimer(kind)
    const timer = window.setTimeout(() => {
      if (!controller.signal.aborted) controller.abort('timeout')
    }, LONG_TASK_TIMEOUT_MS)
    if (kind === 'refresh') refreshTimerRef.current = timer
    else prepareTimerRef.current = timer
  }

  const cancelRefresh = () => {
    if (refreshAbortRef.current && !refreshAbortRef.current.signal.aborted) {
      refreshAbortRef.current.abort('user_cancel')
    }
  }

  const cancelPrepare = () => {
    if (prepareAbortRef.current && !prepareAbortRef.current.signal.aborted) {
      prepareAbortRef.current.abort('user_cancel')
    }
  }

  useEffect(() => {
    let cancelled = false

    const fetchRuntimeHealth = async () => {
      try {
        const res = await fetch('/api/runtime/health')
        if (!res.ok) return
        const data = await res.json()
        if (cancelled) return
        setRuntimeHealth({
          overall: data?.overall === 'healthy' ? 'healthy' : 'degraded',
          checkedAt: typeof data?.checkedAt === 'string' ? data.checkedAt : undefined,
          recommendedMode: data?.recommendedMode === 'full' ? 'full' : 'limited',
          services: data?.services && typeof data.services === 'object' ? data.services : {},
          notes: Array.isArray(data?.notes) ? data.notes.map((n: any) => String(n)) : [],
        })
        const batfishStatus = data?.services?.batfish?.status
        if (typeof batfishStatus === 'string' && batfishStatus.trim()) {
          setPrepareStatus(batfishStatus)
        }
      } catch {
        if (cancelled) return
      }
    }

    fetchRuntimeHealth()
    const timer = window.setInterval(fetchRuntimeHealth, 15000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
      clearTaskTimer('refresh')
      clearTaskTimer('prepare')
      if (refreshAbortRef.current && !refreshAbortRef.current.signal.aborted) {
        refreshAbortRef.current.abort('unmount')
      }
      if (prepareAbortRef.current && !prepareAbortRef.current.signal.aborted) {
        prepareAbortRef.current.abort('unmount')
      }
    }
  }, [setRuntimeHealth])

  const buildRefreshOverrides = (): Record<string, string> => {
    const overrides: Record<string, string> = {}
    if (settings.oobIntf) overrides.PNETLAB_OOB_INTF = settings.oobIntf
    if (settings.deviceGroup) overrides.PNETLAB_DEVICE_GROUP = settings.deviceGroup
    if (settings.pnetlabVmIp) overrides.PNETLAB_VM_IP = settings.pnetlabVmIp
    if (settings.gatewayIp) overrides.PNETLAB_GATEWAY_IP = settings.gatewayIp
    if (settings.nsoAuthgroup) overrides.NSO_AUTHGROUP = settings.nsoAuthgroup
    if (settings.nsoNedId) overrides.NSO_NED_ID = settings.nsoNedId
    return overrides
  }

  const runRefresh = async (overrides: Record<string, string>) => {
    if (isRefreshing) return
    setRefreshError(null)
    setLastRefreshOverrides(overrides)
    setIsRefreshing(true)
    const controller = new AbortController()
    refreshAbortRef.current = controller
    startTaskTimeout('refresh', controller)
    try {
      const res = await fetch('/api/lab/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ overrides }),
        signal: controller.signal,
      })
      const data = await res.json()
      setLabRefreshResult(data)
      const logicalError = !res.ok || data?.status === 'failed' || Boolean(data?.error)
      addEvidence({
        type: 'lab_refresh',
        status: logicalError ? 'error' : 'success',
        title: logicalError ? 'Lab Refresh Failed' : 'Lab Refresh Complete',
        summary: logicalError
          ? String(data?.error || data?.detail || 'Error')
          : `New devices: ${data?.missing?.length || 0}`,
        details: data
      })
      if (logicalError) {
        setRefreshError(String(data?.error || data?.detail || `HTTP ${res.status}`))
        setShowRefreshLog(true)
      }
    } catch (err: any) {
      const reason = String(controller.signal.reason || '')
      if (reason === 'user_cancel') {
        setRefreshError('Refresh cancelled.')
        addEvidence({
          type: 'lab_refresh',
          status: 'warning',
          title: 'Lab Refresh Cancelled',
          summary: 'User cancelled refresh operation.',
          details: { reason: 'user_cancel' },
        })
      } else if (reason === 'timeout') {
        setRefreshError('Refresh timed out. Please retry.')
        addEvidence({
          type: 'lab_refresh',
          status: 'error',
          title: 'Lab Refresh Timeout',
          summary: 'Refresh timed out after 30s.',
          details: { reason: 'timeout' },
        })
      } else {
        setRefreshError(String(err?.message || err || 'Refresh failed'))
      }
    } finally {
      clearTaskTimer('refresh')
      refreshAbortRef.current = null
      setIsRefreshing(false)
    }
  }

  const runPrepare = async (autoInitBatfish: boolean) => {
    if (isPreparing) return
    setPrepareError(null)
    setLastPrepareAutoInit(autoInitBatfish)
    setIsPreparing(true)
    const controller = new AbortController()
    prepareAbortRef.current = controller
    startTaskTimeout('prepare', controller)
    try {
      const res = await fetch('/api/lab/prepare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auto_init_batfish: autoInitBatfish }),
        signal: controller.signal,
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
      if (!res.ok) {
        setPrepareError(String(data?.detail || `HTTP ${res.status}`))
      }
    } catch (err: any) {
      const reason = String(controller.signal.reason || '')
      if (reason === 'user_cancel') {
        setPrepareError('Prepare cancelled.')
        addEvidence({
          type: 'lab_prepare',
          status: 'warning',
          title: 'Batfish Prepare Cancelled',
          summary: 'User cancelled prepare operation.',
          details: { reason: 'user_cancel' },
        })
      } else if (reason === 'timeout') {
        setPrepareError('Prepare timed out. Please retry.')
        addEvidence({
          type: 'lab_prepare',
          status: 'error',
          title: 'Batfish Prepare Timeout',
          summary: 'Prepare timed out after 30s.',
          details: { reason: 'timeout' },
        })
      } else {
        setPrepareError(String(err?.message || err || 'Prepare failed'))
        setPrepareStatus('error')
      }
    } finally {
      clearTaskTimer('prepare')
      prepareAbortRef.current = null
      setIsPreparing(false)
    }
  }

  const handleRefresh = async () => {
    await runRefresh(buildRefreshOverrides())
  }

  const handlePrepare = async () => {
    await runPrepare(false)
  }

  const retryRefresh = async () => {
    if (!lastRefreshOverrides || isRefreshing) return
    await runRefresh(lastRefreshOverrides)
  }

  const retryPrepare = async () => {
    if (isPreparing) return
    await runPrepare(lastPrepareAutoInit)
  }

  const statusColor = (status: string | null) => {
    if (!status) return 'bg-emerald-500'
    if (status === 'ready' || status === 'loaded' || status === 'initialized') return 'bg-emerald-500'
    if (status === 'not_ready') return 'bg-amber-500'
    return 'bg-red-500'
  }

  const runtimeDotClass = runtimeHealth.overall === 'healthy'
    ? 'bg-emerald-500'
    : runtimeHealth.overall === 'degraded'
      ? 'bg-amber-500'
      : 'bg-muted-foreground'

  const serviceBadgeClass = (severity?: string) => {
    if (severity === 'ok') return 'border-emerald-500/30 text-emerald-500 bg-emerald-500/10'
    if (severity === 'warning') return 'border-amber-500/30 text-amber-500 bg-amber-500/10'
    if (severity === 'error') return 'border-rose-500/30 text-rose-500 bg-rose-500/10'
    return 'border-border/70 text-muted-foreground bg-muted/30'
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
              <span className="text-muted-foreground/60">Runtime:</span>
              <div className={`w-1.5 h-1.5 rounded-full ${runtimeDotClass} animate-pulse`} />
              <span className="text-foreground">{runtimeHealth.overall}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className={`w-1.5 h-1.5 rounded-full ${statusColor(prepareStatus)} animate-pulse`} />
              <span className="text-foreground/80">
                Batfish: {prepareStatus || 'unknown'}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className={`px-2 py-0.5 rounded-full border text-[9px] ${serviceBadgeClass(runtimeHealth.services?.nso?.severity)}`}>
                NSO {runtimeHealth.services?.nso?.status || 'unknown'}
              </span>
              <span className={`px-2 py-0.5 rounded-full border text-[9px] ${serviceBadgeClass(runtimeHealth.services?.pnetlab?.severity)}`}>
                PNET {runtimeHealth.services?.pnetlab?.status || 'unknown'}
              </span>
            </div>
            {runtimeHealth.overall === 'degraded' && (
              <span className="text-[9px] px-2 py-0.5 rounded-full border border-amber-500/40 bg-amber-500/10 text-amber-500">
                Limited Mode
              </span>
            )}
          </nav>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1 bg-muted/30 p-1 rounded-lg border border-border/40">
            <button 
              onClick={isRefreshing ? cancelRefresh : handleRefresh}
              className={`h-7 px-3 text-[10px] font-black uppercase tracking-widest text-muted-foreground hover:text-foreground hover:bg-card/50 rounded-md transition-all ${isRefreshing ? 'animate-pulse opacity-50' : ''}`}
            >
              {isRefreshing ? 'Cancel Sync' : 'Refresh'}
            </button>
            <button
              onClick={isPreparing ? cancelPrepare : handlePrepare}
              className={`h-7 px-3 text-[10px] font-black uppercase tracking-widest bg-primary text-primary-foreground shadow-lg rounded-md transition-all hover:scale-105 active:scale-95 ${isPreparing ? 'animate-pulse opacity-70' : ''}`}
            >
              {isPreparing ? 'Cancel Prep' : 'Prepare'}
            </button>
          </div>
          {(refreshError || prepareError) && (
            <div className="flex items-center gap-1.5 text-[9px]">
              {refreshError && (
                <>
                  <button
                    type="button"
                    onClick={retryRefresh}
                    disabled={isRefreshing}
                    className="px-2 py-1 rounded border border-amber-500/30 bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 disabled:opacity-40"
                    title={refreshError}
                  >
                    Retry Refresh
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowRefreshLog(true)}
                    className="px-2 py-1 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-500 hover:bg-cyan-500/20"
                    title="Open latest refresh diagnostics"
                  >
                    Refresh Log
                  </button>
                </>
              )}
              {prepareError && (
                <button
                  type="button"
                  onClick={retryPrepare}
                  disabled={isPreparing}
                  className="px-2 py-1 rounded border border-amber-500/30 bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 disabled:opacity-40"
                  title={prepareError}
                >
                  Retry Prepare
                </button>
              )}
            </div>
          )}
          
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
      {showRefreshLog && (
        <div className="fixed inset-0 z-[120] bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-4xl max-h-[80vh] bg-card border border-border rounded-xl shadow-2xl flex flex-col">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between">
              <div className="text-sm font-semibold">Refresh Diagnostics</div>
              <button
                type="button"
                onClick={() => setShowRefreshLog(false)}
                className="px-2 py-1 text-xs rounded border border-border hover:bg-muted"
              >
                Close
              </button>
            </div>
            <div className="p-4 overflow-auto">
              <pre className="text-xs leading-5 whitespace-pre-wrap break-words text-foreground/90">
                {JSON.stringify(labRefreshResult || { detail: refreshError || 'No refresh result yet.' }, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
