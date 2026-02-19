import { BaseEdge, getSmoothStepPath, Position, type EdgeProps } from '@xyflow/react'

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
  markerEnd,
  label,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: 8,
    offset: 25,
  })

  const edgeData = (data || {}) as Record<string, any>
  const srcIface = edgeData.src_iface || ''
  const dstIface = edgeData.dst_iface || ''

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

  const strokeColor = (style as Record<string, any>)?.stroke || 'hsl(var(--border))'
  const fontSize = 9
  const CHAR_WIDTH = 5.5
  const LABEL_PAD_X = 6
  const LABEL_HEIGHT = 16

  const labelWidth = (text: string) => Math.max(text.length * CHAR_WIDTH + LABEL_PAD_X * 2, 24)

  return (
    <>
      <BaseEdge id={id} path={edgePath} style={style} markerEnd={markerEnd} />
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
            style={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))', fontWeight: 500 }}
          >
            {String(label)}
          </text>
        </g>
      )}
    </>
  )
}
