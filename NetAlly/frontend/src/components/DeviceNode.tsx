/**
 * DeviceNode - Refined for professional network diagrams
 */
import { Handle, Position } from '@xyflow/react'

interface DeviceNodeProps {
  data: {
    label: string
    type: 'router' | 'switch' | 'server'
    platform?: string
    mgmt_ip?: string
  }
  selected?: boolean
}

export default function DeviceNode({ data, selected }: DeviceNodeProps) {
  const getIcon = () => {
    switch (data.type) {
      case 'router': return '⬵'
      case 'switch': return '⇄'
      case 'server': return '▤'
      default: return '○'
    }
  }

  return (
    <div
      className={`
        relative px-4 py-2.5 rounded-lg border transition-all duration-300
        ${selected 
          ? 'bg-primary/20 border-primary ring-4 ring-primary/10 shadow-lg shadow-primary/5' 
          : 'bg-card border-border hover:border-muted-foreground/30 shadow-sm'
        }
      `}
    >
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      
      <div className="flex items-center gap-3">
        <div className={`
          w-8 h-8 rounded-md flex items-center justify-center text-lg
          ${selected ? 'bg-primary text-background' : 'bg-muted text-muted-foreground'}
          transition-colors
        `}>
          {getIcon()}
        </div>
        
        <div className="flex flex-col">
          <span className={`text-[13px] font-bold ${selected ? 'text-foreground' : 'text-foreground/90'}`}>
            {data.label}
          </span>
          {data.mgmt_ip && (
            <span className="text-[10px] font-mono text-muted-foreground leading-none mt-0.5">
              {data.mgmt_ip}
            </span>
          )}
        </div>
      </div>

      <Handle type="source" position={Position.Right} className="!opacity-0" />
      
      {/* Small status indicator dot */}
      <div className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-primary rounded-full border-2 border-background" />
    </div>
  )
}
