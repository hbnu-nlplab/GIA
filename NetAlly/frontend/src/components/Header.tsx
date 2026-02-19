import { useEffect, useRef, useState } from 'react'
import SettingsDialog from './SettingsDialog'
import { useAppStore } from '../store'

const REFRESH_TIMEOUT_MS = 8 * 60_000
const PREPARE_TIMEOUT_MS = 3 * 60_000

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
  const [refreshLogLines, setRefreshLogLines] = useState<string[]>([])
  const [refreshRunState, setRefreshRunState] = useState<'idle' | 'running' | 'success' | 'error'>('idle')
  const [refreshResultCode, setRefreshResultCode] = useState<number | null>(null)
  const refreshAbortRef = useRef<AbortController | null>(null)
  const prepareAbortRef = useRef<AbortController | null>(null)
  const refreshTimerRef = useRef<number | null>(null)
  const prepareTimerRef = useRef<number | null>(null)
  const refreshLogScrollRef = useRef<HTMLDivElement | null>(null)
  const settings = useAppStore(state => state.settings)
  const addEvidence = useAppStore(state => state.addEvidence)
  const setLabPrepare = useAppStore(state => state.setLabPrepare)
  const setLabRefreshResult = useAppStore(state => state.setLabRefreshResult)
  const labRefreshResult = useAppStore(state => state.labRefreshResult)
  const runtimeHealth = useAppStore(state => state.runtimeHealth)
  const setRuntimeHealth = useAppStore(state => state.setRuntimeHealth)
  const viewMode = useAppStore(state => state.viewMode)
  const setViewMode = useAppStore(state => state.setViewMode)

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
    const timeoutMs = kind === 'refresh' ? REFRESH_TIMEOUT_MS : PREPARE_TIMEOUT_MS
    const timer = window.setTimeout(() => {
      if (!controller.signal.aborted) controller.abort('timeout')
    }, timeoutMs)
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

  useEffect(() => {
    if (!showRefreshLog) return
    const el = refreshLogScrollRef.current
    if (!el) return
    el.scrollTop = el.scrollHeight
  }, [showRefreshLog, refreshLogLines])

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

  const appendRefreshLog = (line: string) => {
    const text = String(line || '').trim()
    if (!text) return
    setRefreshLogLines((prev) => [...prev.slice(-799), text])
  }

  const runRefresh = async (overrides: Record<string, string>) => {
    if (isRefreshing) return
    setRefreshError(null)
    setRefreshResultCode(null)
    setRefreshRunState('running')
    setRefreshLogLines([])
    setShowRefreshLog(true)
    setLastRefreshOverrides(overrides)
    setIsRefreshing(true)
    appendRefreshLog(`[${new Date().toLocaleTimeString()}] Refresh requested.`)
    const controller = new AbortController()
    refreshAbortRef.current = controller
    startTaskTimeout('refresh', controller)
    try {
      const requestBody = JSON.stringify({ overrides })
      let data: any = null
      let statusCode = 500

      const streamRes = await fetch('/api/lab/refresh/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: requestBody,
        signal: controller.signal,
      })

      if (streamRes.ok && streamRes.body) {
        const reader = streamRes.body.getReader()
        const decoder = new TextDecoder()
        let sseBuffer = ''
        let streamComplete = false

        const handleSseEvent = (eventName: string, rawData: string) => {
          let payload: any = null
          try {
            payload = JSON.parse(rawData)
          } catch {
            payload = { message: rawData }
          }

          if (eventName === 'status') {
            const msg = String(payload?.message || '').trim()
            if (msg) appendRefreshLog(`[STATUS] ${msg}`)
            return
          }

          if (eventName === 'log') {
            const ts = String(payload?.ts || '').trim()
            const level = String(payload?.level || 'INFO').toUpperCase()
            const loggerName = String(payload?.logger || '').trim()
            const msg = String(payload?.message || '').trim()
            const prefix = [ts, `[${level}]`, loggerName ? `${loggerName}:` : '']
              .filter(Boolean)
              .join(' ')
            appendRefreshLog(msg ? `${prefix} ${msg}`.trim() : prefix)
            return
          }

          if (eventName === 'result') {
            const candidateStatus = Number(payload?.status_code)
            statusCode = Number.isFinite(candidateStatus) ? candidateStatus : 500
            data = payload?.result ?? {}
            return
          }

          if (eventName === 'error') {
            appendRefreshLog(`[ERROR] ${String(payload?.message || 'Unknown stream error')}`)
            return
          }

          if (eventName === 'complete') {
            streamComplete = true
          }
        }

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          sseBuffer += decoder.decode(value, { stream: true })

          while (true) {
            const lfSep = sseBuffer.indexOf('\n\n')
            const crlfSep = sseBuffer.indexOf('\r\n\r\n')
            let sepIdx = -1
            let sepLen = 2
            if (lfSep >= 0 && crlfSep >= 0) {
              if (lfSep < crlfSep) {
                sepIdx = lfSep
                sepLen = 2
              } else {
                sepIdx = crlfSep
                sepLen = 4
              }
            } else if (lfSep >= 0) {
              sepIdx = lfSep
              sepLen = 2
            } else if (crlfSep >= 0) {
              sepIdx = crlfSep
              sepLen = 4
            }
            if (sepIdx < 0) break

            const rawEvent = sseBuffer.slice(0, sepIdx)
            sseBuffer = sseBuffer.slice(sepIdx + sepLen)

            let eventName = 'message'
            const dataLines = rawEvent
              .split(/\r?\n/)
              .reduce<string[]>((acc, line) => {
                if (line.startsWith('event:')) {
                  eventName = line.slice(6).trim() || 'message'
                } else if (line.startsWith('data:')) {
                  acc.push(line.slice(5).trimStart())
                }
                return acc
              }, [])

            if (dataLines.length > 0) {
              handleSseEvent(eventName, dataLines.join('\n'))
            }
          }

          if (streamComplete && data) {
            break
          }
        }
      } else {
        // Backward-compatible fallback for older backend versions.
        const res = await fetch('/api/lab/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: requestBody,
          signal: controller.signal,
        })
        statusCode = res.status
        data = await res.json()
      }

      if (!data) {
        statusCode = 500
        data = { status: 'failed', detail: 'Refresh stream ended without a result payload.' }
      }

      setLabRefreshResult(data)
      setRefreshResultCode(statusCode)
      const logicalError = statusCode >= 400 || data?.status === 'failed' || Boolean(data?.error)
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
        setRefreshRunState('error')
        setRefreshError(String(data?.error || data?.detail || `HTTP ${statusCode}`))
        setShowRefreshLog(true)
        appendRefreshLog('[STATUS] Refresh finished with errors.')
      } else {
        setRefreshRunState('success')
        appendRefreshLog('[STATUS] Refresh completed successfully.')
      }
    } catch (err: any) {
      const reason = String(controller.signal.reason || '')
      if (reason === 'user_cancel') {
        setRefreshRunState('error')
        setRefreshError('Refresh cancelled.')
        appendRefreshLog('[STATUS] Refresh cancelled by user.')
        addEvidence({
          type: 'lab_refresh',
          status: 'warning',
          title: 'Lab Refresh Cancelled',
          summary: 'User cancelled refresh operation.',
          details: { reason: 'user_cancel' },
        })
      } else if (reason === 'timeout') {
        setRefreshRunState('error')
        setRefreshError('Refresh timed out. Please retry.')
        appendRefreshLog('[ERROR] Refresh timed out before completion.')
        addEvidence({
          type: 'lab_refresh',
          status: 'error',
          title: 'Lab Refresh Timeout',
          summary: 'Refresh timed out before completion.',
          details: { reason: 'timeout' },
        })
      } else {
        setRefreshRunState('error')
        setRefreshError(String(err?.message || err || 'Refresh failed'))
        appendRefreshLog(`[ERROR] ${String(err?.message || err || 'Refresh failed')}`)
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
          summary: 'Prepare timed out before completion.',
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
      <header className="h-12 border-b border-border-subtle bg-background px-6 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2.5 group cursor-pointer" onClick={() => window.location.reload()}>
            <div className="w-6 h-6 bg-primary rounded-md flex items-center justify-center group-hover:scale-110 transition-transform">
              <span className="text-xs text-primary-foreground font-bold tracking-tight">NA</span>
            </div>
            <span className="font-bold text-sm tracking-tighter uppercase italic">NetAlly</span>
          </div>
          
          <nav className="flex items-center gap-4 text-ui-xs font-semibold border-l border-border-subtle pl-6 select-none uppercase tracking-wide">
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground/60">Lab:</span>
              <span className="text-foreground border-b border-primary/40 pb-0.5">SP-Core-V5</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground/60">Runtime:</span>
              <div className={`w-1.5 h-1.5 rounded-full ${runtimeDotClass} animate-breathe`} />
              <span className="text-foreground">{runtimeHealth.overall}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className={`w-1.5 h-1.5 rounded-full ${statusColor(prepareStatus)} animate-breathe`} />
              <span className="text-foreground/80">
                Batfish: {prepareStatus || 'unknown'}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className={`px-2 py-0.5 rounded border text-ui-xs ${serviceBadgeClass(runtimeHealth.services?.nso?.severity)}`}>
                NSO {runtimeHealth.services?.nso?.status || 'unknown'}
              </span>
              <span className={`px-2 py-0.5 rounded border text-ui-xs ${serviceBadgeClass(runtimeHealth.services?.pnetlab?.severity)}`}>
                PNET {runtimeHealth.services?.pnetlab?.status || 'unknown'}
              </span>
            </div>
            {runtimeHealth.overall === 'degraded' && (
              <span className="text-ui-xs px-2 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-500">
                Limited Mode
              </span>
            )}
          </nav>
        </div>

        <div className="flex items-center gap-4">
          {/* View Mode Toggle */}
          <div className="flex items-center gap-1 bg-muted p-1 rounded-lg border border-border-subtle">
            <button
              onClick={() => setViewMode('dashboard')}
              className={`h-7 px-3 text-ui-xs font-semibold uppercase tracking-wide rounded-md transition-all ${
                viewMode === 'dashboard' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground hover:bg-card'
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => setViewMode('topology')}
              className={`h-7 px-3 text-ui-xs font-semibold uppercase tracking-wide rounded-md transition-all ${
                viewMode === 'topology' ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground hover:bg-card'
              }`}
            >
              Map View
            </button>
          </div>

          <div className="w-px h-4 bg-border/50" />

          <div className="flex items-center gap-1 bg-muted p-1 rounded-lg border border-border-subtle">
            <button
              onClick={isRefreshing ? cancelRefresh : handleRefresh}
              className={`h-7 px-3 text-ui-xs font-semibold uppercase tracking-wide text-muted-foreground hover:text-foreground hover:bg-card rounded-md transition-all ${isRefreshing ? 'animate-breathe opacity-50' : ''}`}
            >
              {isRefreshing ? 'Cancel Sync' : 'Refresh'}
            </button>
            <button
              onClick={isPreparing ? cancelPrepare : handlePrepare}
              className={`h-7 px-3 text-ui-xs font-semibold uppercase tracking-wide bg-primary text-primary-foreground shadow-elevation-1 rounded-md transition-all hover:scale-105 active:scale-95 ${isPreparing ? 'animate-breathe opacity-70' : ''}`}
            >
              {isPreparing ? 'Cancel Prep' : 'Prepare'}
            </button>
          </div>
          {(refreshError || prepareError || isRefreshing || refreshLogLines.length > 0) && (
            <div className="flex items-center gap-1.5 text-ui-xs">
              {(isRefreshing || refreshError || refreshLogLines.length > 0) && (
                <>
                  {refreshError && (
                    <button
                      type="button"
                      onClick={retryRefresh}
                      disabled={isRefreshing}
                      className="px-2 py-1 rounded border border-amber-500/30 bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 disabled:opacity-40"
                      title={refreshError}
                    >
                      Retry Refresh
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setShowRefreshLog(true)}
                    className="px-2 py-1 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-500 hover:bg-cyan-500/20"
                    title="Open refresh progress/logs"
                  >
                    {isRefreshing ? 'Live Refresh Log' : 'Refresh Log'}
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
            <div className="w-8 h-8 rounded-full bg-primary border border-primary/30 shadow-elevation-1" />
          </div>
        </div>
      </header>

      <SettingsDialog isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)} />
      {showRefreshLog && (
        <div className="fixed inset-0 z-[120] bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-5xl max-h-[84vh] bg-card border border-border rounded-xl shadow-elevation-3 flex flex-col">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="text-ui-lg font-semibold">Refresh Progress</div>
                <span
                  className={`px-2 py-0.5 rounded border text-ui-xs ${
                    refreshRunState === 'running'
                      ? 'border-cyan-500/30 text-cyan-500 bg-cyan-500/10'
                      : refreshRunState === 'success'
                        ? 'border-emerald-500/30 text-emerald-500 bg-emerald-500/10'
                        : refreshRunState === 'error'
                          ? 'border-rose-500/30 text-rose-500 bg-rose-500/10'
                          : 'border-border/70 text-muted-foreground bg-muted/30'
                  }`}
                >
                  {refreshRunState.toUpperCase()}
                </span>
                {refreshResultCode !== null && (
                  <span className="text-ui-xs text-muted-foreground">
                    HTTP {refreshResultCode}
                  </span>
                )}
              </div>
              <button
                type="button"
                onClick={() => setShowRefreshLog(false)}
                className="px-2 py-1 text-xs rounded border border-border hover:bg-muted"
              >
                Close
              </button>
            </div>
            <div className="p-4 overflow-hidden flex-1 flex flex-col gap-3">
              <div className="text-ui-xs text-muted-foreground">
                {isRefreshing
                  ? 'Refresh is running. Live onboarding/telnet logs will appear below.'
                  : 'Latest refresh logs and diagnostics payload.'}
              </div>

              <div
                ref={refreshLogScrollRef}
                className="flex-1 min-h-[260px] rounded-lg border border-border bg-muted/20 p-3 overflow-auto font-mono text-[11px] leading-5 text-foreground/90"
              >
                {refreshLogLines.length > 0 ? (
                  refreshLogLines.map((line, idx) => (
                    <div key={`refresh-log-${idx}`}>{line}</div>
                  ))
                ) : (
                  <div className="text-muted-foreground">No refresh logs yet.</div>
                )}
              </div>

              <div className="rounded-lg border border-border bg-background p-3 overflow-auto max-h-[220px]">
                <div className="text-ui-xs font-semibold mb-2">Diagnostics Payload</div>
                <pre className="text-xs leading-5 whitespace-pre-wrap break-words text-foreground/90">
                  {JSON.stringify(labRefreshResult || { detail: refreshError || 'No refresh result yet.' }, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
