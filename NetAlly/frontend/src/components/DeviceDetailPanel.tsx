import { X, Router, Cable, Network, Activity, Terminal } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useAppStore } from '../store'

interface DeviceInfo {
  name: string
  platform?: string
  config?: string
  routes?: any[]
  interfaces?: any[]
}

export default function DeviceDetailPanel() {
  const { detailView, closeDetail } = useAppStore()
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfo | null>(null)
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'config' | 'routes' | 'interfaces'>('config')

  useEffect(() => {
    if (detailView.isOpen && detailView.type === 'device' && detailView.id) {
      fetchDeviceInfo(detailView.id)
    }
  }, [detailView])

  const fetchDeviceInfo = async (deviceId: string) => {
    setLoading(true)
    try {
      const res = await fetch(`/api/device/${deviceId}`)
      const data = await res.json()
      setDeviceInfo(data)
    } catch (error) {
      console.error('Failed to fetch device info:', error)
    } finally {
      setLoading(false)
    }
  }

  if (!detailView.isOpen || detailView.type !== 'device') return null

  return (
    <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="fixed right-0 top-0 h-full w-full max-w-2xl bg-card border-l border-border shadow-2xl animate-in slide-in-from-right duration-300">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-border bg-muted/20">
          <div className="flex items-center gap-3">
            <Router className="w-5 h-5 text-primary" />
            <div>
              <h2 className="text-sm font-bold uppercase tracking-widest">
                {deviceInfo?.name || detailView.id}
              </h2>
              <p className="text-[10px] text-muted-foreground">
                {deviceInfo?.platform || 'Network Device'}
              </p>
            </div>
          </div>
          <button
            onClick={closeDetail}
            className="p-2 hover:bg-muted rounded-lg transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 p-2 border-b border-border bg-muted/10">
          <button
            onClick={() => setActiveTab('config')}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase transition-all ${
              activeTab === 'config'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'hover:bg-muted text-muted-foreground'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            Configuration
          </button>
          <button
            onClick={() => setActiveTab('routes')}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase transition-all ${
              activeTab === 'routes'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'hover:bg-muted text-muted-foreground'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            Routes
          </button>
          <button
            onClick={() => setActiveTab('interfaces')}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase transition-all ${
              activeTab === 'interfaces'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'hover:bg-muted text-muted-foreground'
            }`}
          >
            <Cable className="w-3.5 h-3.5" />
            Interfaces
          </button>
        </div>

        {/* Content */}
        <div className="p-4 h-[calc(100%-140px)] overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center h-full">
              <Activity className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : (
            <>
              {activeTab === 'config' && (
                <pre className="text-xs bg-muted/50 p-4 rounded-lg overflow-x-auto font-mono">
                  {deviceInfo?.config || 'No configuration available'}
                </pre>
              )}

              {activeTab === 'routes' && (
                <div className="space-y-2">
                  {deviceInfo?.routes && deviceInfo.routes.length > 0 ? (
                    deviceInfo.routes.map((route: any, idx: number) => (
                      <div key={idx} className="bg-muted/50 p-3 rounded-lg">
                        <div className="text-xs font-mono">
                          <span className="text-primary font-bold">{route.network}</span>
                          {' via '}
                          <span className="text-emerald-500">{route.nextHop}</span>
                        </div>
                        <div className="text-[10px] text-muted-foreground mt-1">
                          Protocol: {route.protocol} | Metric: {route.metric}
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-muted-foreground">No routes available</p>
                  )}
                </div>
              )}

              {activeTab === 'interfaces' && (
                <div className="space-y-2">
                  {deviceInfo?.interfaces && deviceInfo.interfaces.length > 0 ? (
                    deviceInfo.interfaces.map((iface: any, idx: number) => (
                      <div key={idx} className="bg-muted/50 p-3 rounded-lg">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold">{iface.name}</span>
                          <span className={`text-[10px] px-2 py-0.5 rounded-full ${
                            iface.status === 'up' 
                              ? 'bg-emerald-500/20 text-emerald-500'
                              : 'bg-rose-500/20 text-rose-500'
                          }`}>
                            {iface.status}
                          </span>
                        </div>
                        {iface.ip && (
                          <div className="text-[10px] text-muted-foreground mt-1 font-mono">
                            {iface.ip}
                          </div>
                        )}
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-muted-foreground">No interfaces available</p>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
