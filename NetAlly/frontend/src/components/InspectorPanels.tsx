import { useState, useEffect } from 'react'
import { useAppStore } from '../store'

interface DeviceData {
  hostname?: string
  platform?: string
  version?: string
  mgmt_ip?: string
  interfaces?: Array<{
    name: string
    ip?: string
    status: string
    protocol?: string
  }>
  bgp_neighbors?: Array<{
    peer: string
    as: string
    state: string
  }>
  routes?: number
  configs?: string
}

export function DeviceInspectorContent({ deviceId }: { deviceId: string }) {
  const [deviceData, setDeviceData] = useState<DeviceData | null>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'overview' | 'interfaces' | 'routing' | 'config'>('overview')

  useEffect(() => {
    const fetchDeviceData = async () => {
      setLoading(true)
      try {
        // Fetch device details from NSO or Batfish
        const res = await fetch(`/api/device/${deviceId}`)
        if (res.ok) {
          const data = await res.json()
          setDeviceData(data)
        }
      } catch (err) {
        console.error('Failed to fetch device data:', err)
      } finally {
        setLoading(false)
      }
    }

    fetchDeviceData()
  }, [deviceId])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-sm text-muted-foreground animate-pulse">Loading device information...</div>
      </div>
    )
  }

  if (!deviceData) {
    return (
      <div className="space-y-4">
        <div className="bg-muted/30 p-4 rounded-lg border border-border/50">
          <h3 className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-3">Device Information</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Hostname:</span>
              <span className="font-mono text-foreground">{deviceId}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Status:</span>
              <span className="text-amber-500">⚠️ No data available</span>
            </div>
          </div>
        </div>
        <div className="bg-amber-500/10 p-3 rounded-lg border border-amber-500/20">
          <p className="text-xs text-amber-600 dark:text-amber-400">
            Device configuration not yet synchronized. Click "Refresh" in the header to fetch the latest data from NSO.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Tab Navigation */}
      <div className="flex gap-1 bg-muted/30 p-1 rounded-lg">
        {(['overview', 'interfaces', 'routing', 'config'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`flex-1 py-2 px-3 text-[10px] font-bold uppercase tracking-wider rounded-md transition-all ${
              activeTab === tab
                ? 'bg-card text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-4">
          <div className="bg-muted/30 p-4 rounded-lg border border-border/50">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-primary/80 mb-3">System Information</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Hostname:</span>
                <span className="font-mono text-foreground">{deviceData.hostname || deviceId}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Platform:</span>
                <span className="font-mono text-foreground">{deviceData.platform || 'Unknown'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Software:</span>
                <span className="font-mono text-foreground text-xs">{deviceData.version || 'Unknown'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Management IP:</span>
                <span className="font-mono text-foreground">{deviceData.mgmt_ip || 'N/A'}</span>
              </div>
            </div>
          </div>

          <div className="bg-muted/30 p-4 rounded-lg border border-border/50">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-primary/80 mb-3">Quick Stats</h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-card p-3 rounded border border-border/30">
                <div className="text-[10px] text-muted-foreground mb-1">Interfaces</div>
                <div className="text-lg font-bold text-foreground">{deviceData.interfaces?.length || 0}</div>
              </div>
              <div className="bg-card p-3 rounded border border-border/30">
                <div className="text-[10px] text-muted-foreground mb-1">BGP Peers</div>
                <div className="text-lg font-bold text-foreground">{deviceData.bgp_neighbors?.length || 0}</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'interfaces' && (
        <div className="space-y-2">
          <h3 className="text-[10px] font-bold uppercase tracking-widest text-primary/80">Interface Status</h3>
          {deviceData.interfaces && deviceData.interfaces.length > 0 ? (
            deviceData.interfaces.map((iface, i) => (
              <div key={i} className="bg-muted/30 p-3 rounded-lg border border-border/50 hover:border-primary/30 transition-colors">
                <div className="flex justify-between items-start mb-2">
                  <span className="font-mono text-sm text-foreground font-bold">{iface.name}</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    iface.status === 'up' ? 'bg-emerald-500/20 text-emerald-500' : 'bg-rose-500/20 text-rose-500'
                  }`}>
                    {iface.status?.toUpperCase() || 'UNKNOWN'}
                  </span>
                </div>
                {iface.ip && (
                  <div className="text-xs text-muted-foreground font-mono">IP: {iface.ip}</div>
                )}
                {iface.protocol && (
                  <div className="text-[10px] text-muted-foreground mt-1">Protocol: {iface.protocol}</div>
                )}
              </div>
            ))
          ) : (
            <div className="text-center py-6 text-muted-foreground text-xs">No interface data available</div>
          )}
        </div>
      )}

      {activeTab === 'routing' && (
        <div className="space-y-3">
          <div className="bg-muted/30 p-4 rounded-lg border border-border/50">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-primary/80 mb-3">BGP Neighbors</h3>
            {deviceData.bgp_neighbors && deviceData.bgp_neighbors.length > 0 ? (
              <div className="space-y-2">
                {deviceData.bgp_neighbors.map((neighbor, i) => (
                  <div key={i} className="flex justify-between items-center p-2 bg-card rounded border border-border/30">
                    <div>
                      <div className="font-mono text-sm text-foreground">{neighbor.peer}</div>
                      <div className="text-[10px] text-muted-foreground">AS {neighbor.as}</div>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      neighbor.state === 'Established' ? 'bg-emerald-500/20 text-emerald-500' : 'bg-amber-500/20 text-amber-500'
                    }`}>
                      {neighbor.state}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-4 text-muted-foreground text-xs">No BGP neighbors configured</div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'config' && (
        <div className="space-y-3">
          <div className="bg-muted/30 p-4 rounded-lg border border-border/50">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-primary/80 mb-3">Running Configuration</h3>
            {deviceData.configs ? (
              <pre className="font-mono text-[11px] text-foreground leading-relaxed overflow-x-auto whitespace-pre-wrap bg-card p-3 rounded border border-border/30 max-h-96">
                {deviceData.configs}
              </pre>
            ) : (
              <div className="text-center py-6 text-muted-foreground text-xs">Configuration not available</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export function EvidenceInspectorContent({ evidenceId }: { evidenceId: string }) {
  const evidenceList = useAppStore(state => state.evidenceList)
  const evidence = evidenceList.find(e => e.id === evidenceId)

  if (!evidence) {
    return <div className="text-sm text-muted-foreground">Evidence not found</div>
  }

  return (
    <div className="space-y-4">
      <div className="bg-muted/30 p-4 rounded-lg border border-border/50">
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-primary/80 mb-3">Evidence Details</h3>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Type:</span>
            <span className="font-mono text-foreground">{evidence.type}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Status:</span>
            <span className={`font-bold ${
              evidence.status === 'success' ? 'text-emerald-500' :
              evidence.status === 'error' ? 'text-rose-500' :
              evidence.status === 'warning' ? 'text-amber-500' : 'text-muted-foreground'
            }`}>{evidence.status.toUpperCase()}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Timestamp:</span>
            <span className="font-mono text-foreground">{evidence.timestamp}</span>
          </div>
        </div>
      </div>

      <div className="bg-muted/30 p-4 rounded-lg border border-border/50">
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-primary/80 mb-3">Raw Output</h3>
        <pre className="font-mono text-[11px] text-foreground leading-relaxed overflow-x-auto whitespace-pre-wrap bg-card p-3 rounded border border-border/30 max-h-96">
          {JSON.stringify(evidence.details, null, 2)}
        </pre>
      </div>
    </div>
  )
}
