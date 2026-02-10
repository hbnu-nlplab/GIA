/**
 * NetworkNode - Hub/Cloud node (e.g., PNETLab bridge/cloud)
 */
import { useMemo, useState } from 'react'
import { Handle, Position } from '@xyflow/react'
import { Cloud } from 'lucide-react'

export default function NetworkNode({ data, selected }: { data: any; selected?: boolean }) {
  const [iconFailed, setIconFailed] = useState(false)

  const iconUrl = useMemo(() => {
    if (!data?.icon) return null
    return `/api/pnetlab/icon/${encodeURIComponent(String(data.icon))}`
  }, [data?.icon])

  return (
    <div
      className={`
        relative px-3 py-2 rounded-xl border transition-all duration-300
        ${selected
          ? 'bg-primary/20 border-primary ring-4 ring-primary/10 shadow-lg shadow-primary/5 scale-105'
          : 'bg-card border-border hover:border-muted-foreground/30 shadow-sm hover:shadow-md'
        }
      `}
    >
      <Handle type="target" position={Position.Left} className="!opacity-0" />

      <div className="flex items-center gap-2">
        <div className="w-8 h-8 rounded-lg flex items-center justify-center border bg-muted/40 border-border">
          {iconUrl && !iconFailed ? (
            <img
              src={iconUrl}
              alt={data?.label || data?.icon || 'network'}
              className="w-5 h-5 object-contain"
              onError={() => setIconFailed(true)}
            />
          ) : (
            <Cloud className="w-4.5 h-4.5 text-muted-foreground" />
          )}
        </div>

        <div className="flex flex-col">
          <span className="text-[12px] font-bold text-foreground/90 leading-none">
            {data?.label || 'network'}
          </span>
          {data?.network_id && (
            <span className="text-[10px] font-mono text-muted-foreground/70 leading-none mt-1">
              net:{String(data.network_id)}
            </span>
          )}
        </div>
      </div>

      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </div>
  )
}

