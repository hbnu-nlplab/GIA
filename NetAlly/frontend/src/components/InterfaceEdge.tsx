import { BaseEdge, getBezierPath, getStraightPath, Position, type EdgeProps } from '@xyflow/react'

export default function InterfaceEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition = Position.Right,
  targetPosition = Position.Left,
  data,
  style,
  label,
}: EdgeProps) {
  const edgeData = (data || {}) as Record<string, any>
  const srcIface = edgeData.src_iface || ''
  const dstIface = edgeData.dst_iface || ''
  const linkstyle = edgeData.linkstyle || 'Bezier'
  const linkcfg = edgeData.linkcfg || {}
  const curviness = linkcfg.curviness ?? 0

  // Map PNETLab curviness (pixel offset, 0-300) to ReactFlow curvature (multiplier, 0.0-1.2)
  const curvature = curviness > 0 ? curviness / 250 : 0.25

  let edgePath: string
  let labelX: number
  let labelY: number

  if (linkstyle === 'Straight') {
    ;[edgePath, labelX, labelY] = getStraightPath({
      sourceX,
      sourceY,
      targetX,
      targetY,
    })
  } else {
    ;[edgePath, labelX, labelY] = getBezierPath({
      sourceX,
      sourceY,
      sourcePosition,
      targetX,
      targetY,
      targetPosition,
      curvature,
    })
  }

  // Compute edge vector for label positioning
  const dx = targetX - sourceX
  const dy = targetY - sourceY
  const edgeLen = Math.sqrt(dx * dx + dy * dy) || 1

  // Fixed pixel offset, clamped to not exceed 40% of edge length
  const LABEL_OFFSET_PX = 35
  const clampedOffset = Math.min(LABEL_OFFSET_PX, edgeLen * 0.4)
  const ratio = clampedOffset / edgeLen

  // Perpendicular vector for shifting labels away from edge path
  const perpX = -dy / edgeLen
  const perpY = dx / edgeLen
  const PERP_SHIFT = 12

  const srcLabelX = sourceX + dx * ratio + perpX * PERP_SHIFT
  const srcLabelY = sourceY + dy * ratio + perpY * PERP_SHIFT
  const dstLabelX = targetX - dx * ratio + perpX * PERP_SHIFT
  const dstLabelY = targetY - dy * ratio + perpY * PERP_SHIFT

  const isHighlighted = Boolean(edgeData.highlight)
  const highlightMode = edgeData.highlightMode as 'path' | 'focus' | undefined

  const strokeColor = (style as Record<string, any>)?.stroke || 'hsl(var(--border))'
  const fontSize = 9
  const CHAR_WIDTH = 5.5
  const LABEL_PAD_X = 6
  const LABEL_HEIGHT = 16

  const labelWidth = (text: string) => Math.max(text.length * CHAR_WIDTH + LABEL_PAD_X * 2, 24)

  return (
    <>
      <style>{`
        @keyframes edgeFlowPath {
          0% { stroke-dashoffset: 24; }
          100% { stroke-dashoffset: 0; }
        }
        @keyframes edgeFocusPulse {
          0%, 100% { stroke-opacity: 0.35; }
          50% { stroke-opacity: 0.75; }
        }
        .edge-anim-path {
          stroke-dasharray: 8 4;
          animation: edgeFlowPath 2s linear infinite;
        }
        .edge-anim-focus {
          stroke-dasharray: 6 6;
          animation: edgeFocusPulse 1.5s ease-in-out infinite;
        }
      `}</style>
      <BaseEdge id={id} path={edgePath} style={style} />
      {isHighlighted && highlightMode === 'path' && (
        <path
          d={edgePath}
          fill="none"
          stroke="#34d399"
          strokeWidth={2.5}
          strokeOpacity={0.6}
          className="edge-anim-path"
          style={{ pointerEvents: 'none' }}
        />
      )}
      {isHighlighted && highlightMode === 'focus' && (
        <path
          d={edgePath}
          fill="none"
          stroke="#fbbf24"
          strokeWidth={3}
          strokeOpacity={0.45}
          className="edge-anim-focus"
          style={{ pointerEvents: 'none' }}
        />
      )}
      {srcIface && (
        <g>
          <rect
            x={srcLabelX - labelWidth(srcIface) / 2}
            y={srcLabelY - LABEL_HEIGHT / 2}
            width={labelWidth(srcIface)}
            height={LABEL_HEIGHT}
            rx={4}
            fill="hsl(var(--card))"
            fillOpacity={0.85}
            stroke={strokeColor}
            strokeWidth={0.5}
            strokeOpacity={0.4}
          />
          <text
            x={srcLabelX}
            y={srcLabelY + 3}
            textAnchor="middle"
            style={{ fontSize, fill: strokeColor, fontWeight: 500, fontFamily: 'JetBrains Mono, monospace' }}
          >
            {srcIface}
          </text>
        </g>
      )}
      {dstIface && (
        <g>
          <rect
            x={dstLabelX - labelWidth(dstIface) / 2}
            y={dstLabelY - LABEL_HEIGHT / 2}
            width={labelWidth(dstIface)}
            height={LABEL_HEIGHT}
            rx={4}
            fill="hsl(var(--card))"
            fillOpacity={0.85}
            stroke={strokeColor}
            strokeWidth={0.5}
            strokeOpacity={0.4}
          />
          <text
            x={dstLabelX}
            y={dstLabelY + 3}
            textAnchor="middle"
            style={{ fontSize, fill: strokeColor, fontWeight: 500, fontFamily: 'JetBrains Mono, monospace' }}
          >
            {dstIface}
          </text>
        </g>
      )}
      {label && (
        <g>
          <rect
            x={labelX - labelWidth(String(label)) / 2}
            y={labelY - LABEL_HEIGHT / 2}
            width={labelWidth(String(label))}
            height={LABEL_HEIGHT}
            rx={4}
            fill="hsl(var(--card))"
            fillOpacity={0.8}
          />
          <text
            x={labelX}
            y={labelY + 3}
            textAnchor="middle"
            style={{ fontSize: 10, fill: strokeColor, fontWeight: 500 }}
          >
            {String(label)}
          </text>
        </g>
      )}
    </>
  )
}
