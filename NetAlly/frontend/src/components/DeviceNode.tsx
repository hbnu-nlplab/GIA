/**
 * DeviceNode - Network equipment icons with lucide-react
 */
import { Handle, Position } from '@xyflow/react'
import { Router, Network, Server, Wifi, HardDrive, Laptop } from 'lucide-react'

interface DeviceNodeProps {
  data: {
    label: string
    type: string
    platform?: string
    mgmt_ip?: string
    highlight?: boolean
    highlightMode?: 'focus' | 'path'
  }
  selected?: boolean
}

export default function DeviceNode({ data, selected }: DeviceNodeProps) {
  const getDeviceIcon = () => {
    const name = data.label.toLowerCase()
    const platform = data.platform?.toLowerCase() || ''
    const explicitType = (data as any).device_type?.toLowerCase()
    
    // 1. Explicit type from backend
    if (explicitType === 'router') return <Router className="w-5 h-5" />
    if (explicitType === 'switch') return <Network className="w-5 h-5" />
    if (explicitType === 'server') return <Server className="w-5 h-5" />
    
    // 2. Fallback to name-based detection
    // Router detection
    if (name.includes('pe') || name.startsWith('p') || 
        name.includes('router') || platform.includes('router')) {
      return <Router className="w-5 h-5" />
    }
    
    // Switch detection (Spine/Leaf/Switch)
    if (name.includes('spine') || name.includes('leaf') || 
        name.includes('sw') || name.includes('switch')) {
      return <Network className="w-5 h-5" />
    }
    
    // Server/Host detection
    if (name.includes('srv') || name.includes('server') || 
        name.includes('host') || platform.includes('server')) {
      return <Server className="w-5 h-5" />
    }
    
    // PC/Client detection
    if (name.includes('pc') || name.includes('client') || name.includes('ce')) {
      return <Laptop className="w-5 h-5" />
    }
    
    // Wireless AP
    if (name.includes('ap') || name.includes('wifi') || name.includes('wireless')) {
      return <Wifi className="w-5 h-5" />
    }
    
    // Firewall/Security
    if (name.includes('fw') || name.includes('firewall') || name.includes('asa')) {
      return <HardDrive className="w-5 h-5" />
    }
    
    // Default: generic network device
    return <Network className="w-5 h-5" />
  }

  const getTypeColor = () => {
    const name = data.label.toLowerCase()
    if (name.includes('pe') || name.includes('router')) return 'bg-blue-500/20 text-blue-500 border-blue-500/30'
    if (name.includes('spine')) return 'bg-purple-500/20 text-purple-500 border-purple-500/30'
    if (name.includes('leaf')) return 'bg-emerald-500/20 text-emerald-500 border-emerald-500/30'
    if (name.includes('server')) return 'bg-orange-500/20 text-orange-500 border-orange-500/30'
    return 'bg-slate-500/20 text-slate-500 border-slate-500/30'
  }

  return (
    <div
      className={`
        relative px-4 py-2.5 rounded-xl border transition-all duration-300
        ${selected 
          ? 'bg-primary/20 border-primary ring-4 ring-primary/10 shadow-lg shadow-primary/5 scale-105' 
          : data.highlight
            ? (data.highlightMode === 'path'
                ? 'bg-emerald-500/10 border-emerald-500/50 ring-4 ring-emerald-500/10 shadow-lg shadow-emerald-500/10'
                : 'bg-orange-500/10 border-orange-500/50 ring-4 ring-orange-500/10 shadow-lg shadow-orange-500/10'
              )
            : 'bg-card border-border hover:border-muted-foreground/30 shadow-sm hover:shadow-md'
        }
      `}
    >
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      
      <div className="flex items-center gap-3">
        <div className={`
          w-10 h-10 rounded-lg flex items-center justify-center border
          ${selected
            ? 'bg-primary/30 text-primary border-primary'
            : data.highlight
              ? (data.highlightMode === 'path'
                  ? 'bg-emerald-500/20 text-emerald-500 border-emerald-500/40'
                  : 'bg-orange-500/20 text-orange-500 border-orange-500/40'
                )
              : getTypeColor()
          }
          transition-all
        `}>
          {getDeviceIcon()}
        </div>
        
        <div className="flex flex-col">
          <span className={`text-sm font-bold ${selected ? 'text-foreground' : 'text-foreground/90'}`}>
            {data.label}
          </span>
          {data.platform && (
            <span className="text-[10px] text-muted-foreground leading-none mt-0.5">
              {data.platform}
            </span>
          )}
          {data.mgmt_ip && (
            <span className="text-[10px] font-mono text-muted-foreground/70 leading-none mt-0.5">
              {data.mgmt_ip}
            </span>
          )}
        </div>
      </div>

      <Handle type="source" position={Position.Right} className="!opacity-0" />
      
      {/* Status indicator */}
      {selected && (
        <div className="absolute -top-1 -right-1 w-3 h-3 bg-primary rounded-full border-2 border-background animate-pulse" />
      )}
    </div>
  )
}
