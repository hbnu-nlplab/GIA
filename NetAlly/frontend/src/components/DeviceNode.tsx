/**
 * DeviceNode - Network equipment with Grafana-style NOC visuals
 */
import { useMemo, useState } from 'react'
import { Handle, Position } from '@xyflow/react'
import { Router, Network, Server, Wifi, HardDrive, Laptop } from 'lucide-react'

const HANDLE_POSITIONS = [Position.Top, Position.Right, Position.Bottom, Position.Left]

interface DeviceNodeProps {
  data: {
    label: string
    type: string
    platform?: string
    mgmt_ip?: string
    icon?: string
    highlight?: boolean
    highlightMode?: 'focus' | 'path'
  }
  selected?: boolean
}

export default function DeviceNode({ data, selected }: DeviceNodeProps) {
  const [staticFailed, setStaticFailed] = useState(false)
  const [proxyFailed, setProxyFailed] = useState(false)

  const pnetlabIconUrl = useMemo(() => {
    if (!data.icon) return null
    return `/pnetlab-icons/${encodeURIComponent(data.icon)}`
  }, [data.icon])

  const pnetlabProxyUrl = useMemo(() => {
    if (!data.icon) return null
    return `/api/pnetlab/icon/${encodeURIComponent(data.icon)}`
  }, [data.icon])

  const getDeviceIcon = () => {
    const name = data.label.toLowerCase()
    const platform = data.platform?.toLowerCase() || ''
    const explicitType = (data as any).device_type?.toLowerCase()

    if (explicitType === 'router') return <Router className="w-5 h-5" />
    if (explicitType === 'switch') return <Network className="w-5 h-5" />
    if (explicitType === 'server') return <Server className="w-5 h-5" />

    if (name.includes('pe') || name.startsWith('p') ||
        name.includes('router') || platform.includes('router')) {
      return <Router className="w-5 h-5" />
    }
    if (name.includes('spine') || name.includes('leaf') ||
        name.includes('sw') || name.includes('switch')) {
      return <Network className="w-5 h-5" />
    }
    if (name.includes('srv') || name.includes('server') ||
        name.includes('host') || platform.includes('server')) {
      return <Server className="w-5 h-5" />
    }
    if (name.includes('pc') || name.includes('client') || name.includes('ce')) {
      return <Laptop className="w-5 h-5" />
    }
    if (name.includes('ap') || name.includes('wifi') || name.includes('wireless')) {
      return <Wifi className="w-5 h-5" />
    }
    if (name.includes('fw') || name.includes('firewall') || name.includes('asa')) {
      return <HardDrive className="w-5 h-5" />
    }
    return <Network className="w-5 h-5" />
  }

  const getAccentClass = () => {
    const name = data.label.toLowerCase()
    if (name.includes('pe') || name.includes('router')) return 'node-accent-blue'
    if (name.includes('spine')) return 'node-accent-purple'
    if (name.includes('leaf')) return 'node-accent-green'
    if (name.includes('server') || name.includes('srv')) return 'node-accent-amber'
    if (name.includes('nso') || name.includes('docker') || name.includes('netally')) return 'node-accent-amber'
    return 'node-accent-muted'
  }

  const getIconColor = () => {
    const name = data.label.toLowerCase()
    if (name.includes('pe') || name.includes('router')) return 'text-blue-400'
    if (name.includes('spine')) return 'text-purple-400'
    if (name.includes('leaf')) return 'text-emerald-400'
    if (name.includes('server') || name.includes('srv')) return 'text-amber-400'
    if (name.includes('nso') || name.includes('docker') || name.includes('netally')) return 'text-amber-400'
    return 'text-slate-400'
  }

  return (
    <div
      className={`
        relative px-4 py-2.5 rounded-xl border transition-all duration-200
        ${selected
          ? 'bg-primary/8 border-primary shadow-glow-primary scale-[1.03]'
          : data.highlight
            ? (data.highlightMode === 'path'
                ? 'bg-emerald-500/6 border-emerald-400/40 shadow-glow-ok'
                : 'bg-amber-500/6 border-amber-400/40 shadow-[0_0_10px_-2px_hsl(38_90%_55%/0.2)]'
              )
            : `bg-card border-border-subtle hover:border-border-strong shadow-elevation-1 hover:shadow-elevation-2 ${getAccentClass()}`
        }
      `}
    >
      {/* 4-way handles for dynamic edge routing */}
      {HANDLE_POSITIONS.map((pos) => (
        <Handle key={`src-${pos}`} type="source" position={pos} id={`src-${pos}`}
          className="!opacity-0 !w-0 !h-0" />
      ))}
      {HANDLE_POSITIONS.map((pos) => (
        <Handle key={`tgt-${pos}`} type="target" position={pos} id={`tgt-${pos}`}
          className="!opacity-0 !w-0 !h-0" />
      ))}

      <div className="flex items-center gap-3">
        <div className={`
          w-9 h-9 rounded-md flex items-center justify-center
          ${selected
            ? 'text-primary'
            : data.highlight
              ? (data.highlightMode === 'path' ? 'text-emerald-400' : 'text-amber-400')
              : getIconColor()
          }
        `}>
          {pnetlabIconUrl && !staticFailed ? (
            <img
              src={pnetlabIconUrl}
              alt={data.icon || data.label}
              className="w-6 h-6 object-contain"
              onError={() => setStaticFailed(true)}
            />
          ) : pnetlabProxyUrl && !proxyFailed ? (
            <img
              src={pnetlabProxyUrl}
              alt={data.icon || data.label}
              className="w-6 h-6 object-contain"
              onError={() => setProxyFailed(true)}
            />
          ) : (
            getDeviceIcon()
          )}
        </div>

        <div className="flex flex-col">
          <span className={`text-ui-lg font-semibold ${selected ? 'text-foreground' : 'text-foreground/90'}`}>
            {data.label}
          </span>
          {data.platform && (
            <span className="text-ui-xs text-muted-foreground leading-none mt-0.5">
              {data.platform}
            </span>
          )}
          {data.mgmt_ip && (
            <span className="text-ui-xs font-mono text-muted-foreground/70 leading-none mt-0.5">
              {data.mgmt_ip}
            </span>
          )}
        </div>
      </div>

      {selected && (
        <div className="absolute -top-1 -right-1 w-3 h-3 bg-primary rounded-full border-2 border-background animate-breathe" />
      )}
    </div>
  )
}
