/**
 * NetworkNode - Hub/Cloud node with Grafana-style NOC visuals
 */
import { useMemo, useState } from 'react'
import { Handle, Position } from '@xyflow/react'
import { Cloud } from 'lucide-react'

const HANDLE_POSITIONS = [Position.Top, Position.Right, Position.Bottom, Position.Left]

export default function NetworkNode({ data, selected }: { data: any; selected?: boolean }) {
  const [staticFailed, setStaticFailed] = useState(false)
  const [proxyFailed, setProxyFailed] = useState(false)
  const highlighted = Boolean(data?.highlight)
  const isPath = data?.highlightMode === 'path'

  const iconUrl = useMemo(() => {
    if (!data?.icon) return null
    return `/pnetlab-icons/${encodeURIComponent(String(data.icon))}`
  }, [data?.icon])

  const proxyUrl = useMemo(() => {
    if (!data?.icon) return null
    return `/api/pnetlab/icon/${encodeURIComponent(String(data.icon))}`
  }, [data?.icon])

  return (
    <div
      className={`
        relative px-3 py-2 rounded-xl border transition-all duration-200
        ${selected
          ? 'bg-primary/8 border-primary shadow-glow-primary scale-[1.03]'
          : highlighted
            ? (isPath
                ? 'bg-emerald-500/6 border-emerald-400/40 shadow-glow-ok'
                : 'bg-amber-500/6 border-amber-400/40 shadow-[0_0_10px_-2px_hsl(38_90%_55%/0.2)]'
              )
            : 'bg-card border-border-subtle hover:border-border-strong shadow-elevation-1 hover:shadow-elevation-2'
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

      <div className="flex items-center gap-2">
        <div className="w-7 h-7 rounded flex items-center justify-center">
          {iconUrl && !staticFailed ? (
            <img
              src={iconUrl}
              alt={data?.label || data?.icon || 'network'}
              className="w-5 h-5 object-contain"
              onError={() => setStaticFailed(true)}
            />
          ) : proxyUrl && !proxyFailed ? (
            <img
              src={proxyUrl}
              alt={data?.label || data?.icon || 'network'}
              className="w-5 h-5 object-contain"
              onError={() => setProxyFailed(true)}
            />
          ) : (
            <Cloud className="w-4.5 h-4.5 text-muted-foreground" />
          )}
        </div>

        <div className="flex flex-col">
          <span className="text-ui-base font-semibold text-foreground/90 leading-none">
            {data?.label || 'network'}
          </span>
          {data?.network_id && (
            <span className="text-ui-xs font-mono text-muted-foreground/70 leading-none mt-1">
              net:{String(data.network_id)}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
