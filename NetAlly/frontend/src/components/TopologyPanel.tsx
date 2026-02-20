import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  Node,
  Edge,
  Position,
  useNodesState,
  useEdgesState,
} from '@xyflow/react'
import { Zap, RefreshCcw, AlertCircle, Layers, Network, FlaskConical, TestTube2 } from 'lucide-react'
import DeviceNode from './DeviceNode'
import NetworkNode from './NetworkNode'
import InterfaceEdge from './InterfaceEdge'
import { useAppStore, ChatContextDevice, TopologyDeviceSummary } from '../store'
import dagre from 'dagre'

interface ApiNode {
  id: string
  type: string
  data: Record<string, any>
}

interface ApiEdge {
  source: string
  target: string
  label?: string
  style?: Record<string, any>
}

interface ApiTopologyResponse {
  nodes?: ApiNode[]
  edges?: ApiEdge[]
  error?: string
}

interface NodeContextMenuState {
  nodeId: string
  nodeType: string
  x: number
  y: number
}

const nodeTypes: Record<string, any> = {
  device: DeviceNode,
  network: NetworkNode,
}

const edgeTypes: Record<string, any> = {
  interface: InterfaceEdge,
}

const toNodeKeyVariants = (value: unknown): string[] => {
  const raw = String(value ?? '').trim().toLowerCase()
  if (!raw) return []

  const compact = raw.replace(/^['"`]+|['"`]+$/g, '').replace(/\s+/g, '')
  if (!compact) return []

  const out = new Set<string>()
  out.add(compact)
  out.add(compact.replace(/_/g, '-'))

  if (!compact.startsWith('net:')) {
    const dotIndex = compact.indexOf('.')
    if (dotIndex > 0) {
      const short = compact.slice(0, dotIndex)
      if (short) {
        out.add(short)
        out.add(short.replace(/_/g, '-'))
      }
    }
  }

  return Array.from(out)
}

const primaryNodeKey = (value: unknown): string => toNodeKeyVariants(value)[0] || ''

const makeUndirectedEdgeKey = (a: unknown, b: unknown): string => {
  const ka = primaryNodeKey(a)
  const kb = primaryNodeKey(b)
  if (!ka || !kb) return ''
  return ka < kb ? `${ka}<->${kb}` : `${kb}<->${ka}`
}

const collectAliasCandidates = (node: Node): string[] => {
  const data = ((node.data || {}) as Record<string, any>)
  const raw = [
    node.id,
    data.label,
    data.hostname,
    data.name,
    data.node_id,
    data.alias,
  ]

  if (Array.isArray(data.aliases)) raw.push(...data.aliases)
  else if (typeof data.aliases === 'string') raw.push(...data.aliases.split(','))

  return raw
    .filter((v) => v != null && String(v).trim().length > 0)
    .map((v) => String(v))
}

const NODE_WIDTH = 220
const NODE_HEIGHT = 80
const NET_NODE_WIDTH = 160
const NET_NODE_HEIGHT = 60

const getLayoutedElements = (nodes: Node[], edges: Edge[], direction = 'TB') => {
  const dagreGraph = new dagre.graphlib.Graph()
  dagreGraph.setDefaultEdgeLabel(() => ({}))
  dagreGraph.setGraph({ rankdir: direction, nodesep: 150, ranksep: 200 })

  nodes.forEach((node) => {
    const isNet = node.type === 'network'
    dagreGraph.setNode(node.id, {
      width: isNet ? NET_NODE_WIDTH : NODE_WIDTH,
      height: isNet ? NET_NODE_HEIGHT : NODE_HEIGHT,
    })
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target)
  });

  dagre.layout(dagreGraph)

  const newNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id)
    const isNet = node.type === 'network'
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - (isNet ? NET_NODE_WIDTH : NODE_WIDTH) / 2,
        y: nodeWithPosition.y - (isNet ? NET_NODE_HEIGHT : NODE_HEIGHT) / 2,
      },
    }
  })

  return { nodes: newNodes, edges }
}

/**
 * Compute optimal handle sides based on relative node positions.
 * Uses atan2 angle from source center to target center, mapped to
 * the nearest cardinal direction (Top/Right/Bottom/Left).
 */
function computeHandleSides(
  srcX: number, srcY: number, srcW: number, srcH: number,
  tgtX: number, tgtY: number, tgtW: number, tgtH: number,
): { sourceHandle: string; targetHandle: string } {
  const dx = (tgtX + tgtW / 2) - (srcX + srcW / 2)
  const dy = (tgtY + tgtH / 2) - (srcY + srcH / 2)
  const angle = Math.atan2(dy, dx) * (180 / Math.PI)

  let srcSide: Position
  let tgtSide: Position

  if (angle >= -45 && angle < 45) {
    srcSide = Position.Right; tgtSide = Position.Left
  } else if (angle >= 45 && angle < 135) {
    srcSide = Position.Bottom; tgtSide = Position.Top
  } else if (angle >= -135 && angle < -45) {
    srcSide = Position.Top; tgtSide = Position.Bottom
  } else {
    srcSide = Position.Left; tgtSide = Position.Right
  }

  return {
    sourceHandle: `src-${srcSide}`,
    targetHandle: `tgt-${tgtSide}`,
  }
}

export default function TopologyPanel() {
  const { setSelectedNode, openDetail, theme, topologySource, setTopologySource, viz, setTopologyDevices, setChatContextDevice } = useAppStore(state => ({
    setSelectedNode: state.setSelectedNode,
    openDetail: state.openDetail,
    theme: state.theme,
    topologySource: state.topologySource,
    setTopologySource: state.setTopologySource,
    viz: state.viz,
    setTopologyDevices: state.setTopologyDevices,
    setChatContextDevice: state.setChatContextDevice,
  }))

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const nodesRef = useRef<Node[]>([])
  const edgesRef = useRef<Edge[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [analyzingReachability, setAnalyzingReachability] = useState(false)
  const [layer, setLayer] = useState<'l1' | 'l3'>('l1')
  const [topologyRevision, setTopologyRevision] = useState(0)
  const [nodeContextMenu, setNodeContextMenu] = useState<NodeContextMenuState | null>(null)
  const fetchSeqRef = useRef(0)
  const fetchAbortRef = useRef<AbortController | null>(null)
  const panelRef = useRef<HTMLDivElement | null>(null)

  // If the user has never selected a topology source before, we can safely
  // auto-fallback to PNETLab when Batfish returns no nodes (common in demos
  // where Batfish/NSO isn't running).
  const hasPersistedTopologySource = useMemo(() => {
    try {
      return localStorage.getItem('topologySource') != null
    } catch {
      return false
    }
  }, [])

  const vizEdgeColor = viz?.mode === 'path' ? (theme === 'dark' ? '#34d399' : '#059669') : (theme === 'dark' ? '#fb923c' : '#f97316')

  const toChatContext = (node: Node): ChatContextDevice => {
    const data = (node.data || {}) as Record<string, any>
    return {
      id: String(node.id),
      label: String(data.label || node.id),
      platform: data.platform ? String(data.platform) : undefined,
      deviceType: data.device_type ? String(data.device_type) : undefined,
      source: 'map',
    }
  }

  const fetchTopology = useCallback(async () => {
    const requestSeq = fetchSeqRef.current + 1
    fetchSeqRef.current = requestSeq
    fetchAbortRef.current?.abort()
    const controller = new AbortController()
    fetchAbortRef.current = controller

    let switchingSource = false
    setLoading(true)
    setError(null)
    try {
      // API 선택: Batfish vs PNETLab
      const apiUrl = topologySource === 'pnetlab'
        ? '/api/topology/pnetlab'
        : `/api/topology?layer=${layer}`

      const res = await fetch(apiUrl, { signal: controller.signal })
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`)
      const data: ApiTopologyResponse = await res.json()

      if (requestSeq !== fetchSeqRef.current) return

      if (typeof data?.error === 'string' && data.error.trim()) {
        throw new Error(data.error)
      }

      if (!data || !Array.isArray(data.nodes)) {
        throw new Error('Invalid topology data format')
      }

      // Auto-switch to PNETLab when Batfish returns no useful topology
      // (no nodes, or nodes but no edges — typical when Batfish snapshot is not loaded).
      if (
        topologySource === 'batfish' &&
        Array.isArray(data.nodes) &&
        (data.nodes.length === 0 || (data.edges || []).length === 0)
      ) {
        switchingSource = true
        setTopologySource('pnetlab')
        return
      }

      // Position은 모든 노드에 있어야만 raw layout을 신뢰한다.
      const hasCompletePositions =
        data.nodes.length > 0 &&
        data.nodes.every((n: any) => Number.isFinite(n?.position?.x) && Number.isFinite(n?.position?.y))

      const flowNodes: Node[] = data.nodes.map((n: ApiNode & { position?: { x: number, y: number } }) => ({
        id: n.id,
        type: n.type === 'network' ? 'network' : 'device',
        // Position set이 완전할 때만 원본 좌표를 그대로 사용한다.
        position: hasCompletePositions && n.position
          ? { x: Number(n.position.x), y: Number(n.position.y) }
          : { x: 0, y: 0 },
        data: {
          label: n.id,
          platform: n.data?.platform || n.data?.template || n.data?.kind || '',
          device_type: n.data?.device_type || 'router',
          ...n.data
        },
      }))

      // Build raw edges (handles will be computed after node positioning)
      const rawEdges: Edge[] = (data.edges || []).map((e: ApiEdge, i: number) => {
        const backendStyle = (e.style || {}) as Record<string, any>
        const edgeColor = backendStyle.stroke || 'hsl(var(--muted-foreground) / 0.5)'
        const mergedStyle = { ...backendStyle, stroke: edgeColor, strokeWidth: backendStyle.strokeWidth || 3 }
        const hasIface = !!(e as any).data?.src_iface
        return {
          id: `e-${e.source}-${e.target}-${i}`,
          source: e.source,
          target: e.target,
          label: e.label,
          type: hasIface ? 'interface' : 'default',
          animated: false,
          data: {
            ...((e as any).data || {}),
            __baseStyle: mergedStyle,
            __baseMarker: undefined,
            __baseAnimated: false,
            __baseLabel: e.label || '',
            __reachability: null,
          },
          style: mergedStyle,
          labelStyle: { fill: 'hsl(var(--muted-foreground))', fontSize: 10, fontWeight: 500 },
          labelBgStyle: { fill: 'hsl(var(--card))', fillOpacity: 0.8 },
          labelBgPadding: [4, 2] as [number, number],
          labelBgBorderRadius: 4,
        }
      })

      const deviceCatalog: TopologyDeviceSummary[] = flowNodes
        .filter((n) => n.type === 'device' && !String(n.id).startsWith('net:'))
        .map((n) => ({
          id: String(n.id),
          label: String(((n.data || {}) as Record<string, any>).label || n.id),
          platform: ((n.data || {}) as Record<string, any>).platform
            ? String(((n.data || {}) as Record<string, any>).platform)
            : undefined,
          deviceType: ((n.data || {}) as Record<string, any>).device_type
            ? String(((n.data || {}) as Record<string, any>).device_type)
            : undefined,
        }))

      // Position nodes first (raw coords or dagre), then compute handle sides
      let finalNodes: Node[]
      if (hasCompletePositions) {
        finalNodes = flowNodes
      } else {
        const { nodes: layoutedNodes } = getLayoutedElements(flowNodes, rawEdges)
        finalNodes = layoutedNodes
      }

      // Build position lookup for handle computation
      const nodePositions = new Map<string, { x: number; y: number; w: number; h: number }>()
      for (const n of finalNodes) {
        const isNet = n.type === 'network'
        nodePositions.set(n.id, {
          x: n.position.x,
          y: n.position.y,
          w: isNet ? NET_NODE_WIDTH : NODE_WIDTH,
          h: isNet ? NET_NODE_HEIGHT : NODE_HEIGHT,
        })
      }

      // Assign optimal sourceHandle/targetHandle per edge
      const finalEdges = rawEdges.map((edge) => {
        const src = nodePositions.get(edge.source)
        const tgt = nodePositions.get(edge.target)
        if (src && tgt) {
          const sides = computeHandleSides(src.x, src.y, src.w, src.h, tgt.x, tgt.y, tgt.w, tgt.h)
          return { ...edge, sourceHandle: sides.sourceHandle, targetHandle: sides.targetHandle }
        }
        return edge
      })

      nodesRef.current = finalNodes
      edgesRef.current = finalEdges
      setNodes(finalNodes)
      setEdges(finalEdges)
      setTopologyDevices(deviceCatalog)
      setTopologyRevision((v) => v + 1)
    } catch (err: any) {
      if (err?.name === 'AbortError') return
      if (requestSeq !== fetchSeqRef.current) return
      console.error('Failed to fetch topology:', err)
      setError(err.message || 'Failed to load topology')
      setTopologyDevices([])
    } finally {
      if (requestSeq === fetchSeqRef.current && !switchingSource) setLoading(false)
    }
  }, [layer, topologySource, setNodes, setEdges, hasPersistedTopologySource, setTopologySource, setTopologyDevices])

  // Apply visualization overlay to existing nodes/edges whenever viz changes.
  useEffect(() => {
    const currentNodes = nodesRef.current
    const currentEdges = edgesRef.current
    if (currentNodes.length === 0 && currentEdges.length === 0) {
      return
    }

    const aliasToNodeId = new Map<string, string>()
    for (const node of currentNodes) {
      for (const candidate of collectAliasCandidates(node)) {
        for (const key of toNodeKeyVariants(candidate)) {
          if (!aliasToNodeId.has(key)) aliasToNodeId.set(key, node.id)
        }
      }
    }

    const resolveNodeId = (value: unknown): string | null => {
      for (const key of toNodeKeyVariants(value)) {
        const hit = aliasToNodeId.get(key)
        if (hit) return hit
      }
      return null
    }

    const adjacency = new Map<string, Set<string>>()
    const existingEdgeKeys = new Set<string>()
    for (const e of currentEdges) {
      const s = primaryNodeKey(e.source)
      const t = primaryNodeKey(e.target)
      if (!s || !t) continue
      const key = makeUndirectedEdgeKey(s, t)
      if (key) existingEdgeKeys.add(key)

      if (!adjacency.has(s)) adjacency.set(s, new Set<string>())
      if (!adjacency.has(t)) adjacency.set(t, new Set<string>())
      adjacency.get(s)!.add(t)
      adjacency.get(t)!.add(s)
    }

    const highlightedNodeIds = new Set<string>()
    const highlightedEdgeKeys = new Set<string>()
    const unmatchedNodeHints: string[] = []
    const unmatchedEdgeHints: string[] = []
    let matchedRequestedNodes = 0
    let matchedRequestedEdges = 0
    let hubAssistedEdges = 0

    if (viz) {
      for (const n of viz.nodes || []) {
        const resolved = resolveNodeId(n)
        if (resolved) {
          highlightedNodeIds.add(resolved)
          matchedRequestedNodes += 1
        } else {
          unmatchedNodeHints.push(String(n))
        }
      }

      for (const edge of viz.edges || []) {
        const srcResolved = resolveNodeId(edge.source)
        const dstResolved = resolveNodeId(edge.target)
        const srcKey = primaryNodeKey(srcResolved || edge.source)
        const dstKey = primaryNodeKey(dstResolved || edge.target)
        if (!srcKey || !dstKey) continue

        if (srcResolved) highlightedNodeIds.add(srcResolved)
        if (dstResolved) highlightedNodeIds.add(dstResolved)

        const direct = makeUndirectedEdgeKey(srcKey, dstKey)
        if (direct && existingEdgeKeys.has(direct)) {
          highlightedEdgeKeys.add(direct)
          matchedRequestedEdges += 1
          continue
        }

        const srcNeighbors = adjacency.get(srcKey) || new Set<string>()
        const dstNeighbors = adjacency.get(dstKey) || new Set<string>()
        const commonHubs = Array.from(srcNeighbors).filter(
          (neighbor) => neighbor.startsWith('net:') && dstNeighbors.has(neighbor)
        )

        if (commonHubs.length > 0) {
          for (const hubKey of commonHubs) {
            const sHub = makeUndirectedEdgeKey(srcKey, hubKey)
            const dHub = makeUndirectedEdgeKey(dstKey, hubKey)
            if (sHub) highlightedEdgeKeys.add(sHub)
            if (dHub) highlightedEdgeKeys.add(dHub)
            const hubNodeId = aliasToNodeId.get(hubKey)
            if (hubNodeId) highlightedNodeIds.add(hubNodeId)
          }
          matchedRequestedEdges += 1
          hubAssistedEdges += 1
          continue
        }
        unmatchedEdgeHints.push(`${String(edge.source)} -> ${String(edge.target)}`)
      }
    }

    setNodes((prev) => {
      const nextMode = viz?.mode || 'focus'
      return prev.map((node) => {
        const nextHighlight = Boolean(viz) && highlightedNodeIds.has(node.id)
        if ((node.data as any)?.highlight === nextHighlight && (node.data as any)?.highlightMode === nextMode) {
          return node
        }
        return {
          ...node,
          data: {
            ...(node.data || {}),
            highlight: nextHighlight,
            highlightMode: nextMode,
          },
        }
      })
    })

    setEdges((prev) => prev.map((edge) => {
      const edgeData = ((edge.data || {}) as Record<string, any>)
      const baseStyle = edgeData.__baseStyle || { stroke: 'hsl(var(--border))', strokeWidth: 2 }
      const baseAnimated = typeof edgeData.__baseAnimated === 'boolean' ? edgeData.__baseAnimated : Boolean(edge.animated)
      const baseLabel = typeof edgeData.__baseLabel === 'string' ? edgeData.__baseLabel : (edge.label || '')
      const reachability = edgeData.__reachability && typeof edgeData.__reachability === 'object'
        ? (edgeData.__reachability as Record<string, any>)
        : null
      const preVizStyle = reachability?.style && typeof reachability.style === 'object'
        ? (reachability.style as Record<string, any>)
        : baseStyle
      const preVizAnimated = typeof reachability?.animated === 'boolean' ? reachability.animated : baseAnimated
      const preVizLabel = typeof reachability?.label === 'string' && reachability.label.length > 0
        ? reachability.label
        : baseLabel
      const highlighted =
        Boolean(viz) &&
        highlightedEdgeKeys.has(makeUndirectedEdgeKey(edge.source, edge.target))

      const style = highlighted
        ? {
          ...preVizStyle,
          stroke: vizEdgeColor,
          strokeWidth: Math.max(Number(preVizStyle.strokeWidth) || 2, 4),
        }
        : preVizStyle

      return {
        ...edge,
        style,
        markerEnd: undefined,
        animated: preVizAnimated,
        label: preVizLabel,
      }
    }))

    if (!viz) {
      return
    }
  }, [viz, topologyRevision, setNodes, setEdges, vizEdgeColor])

  useEffect(() => {
    nodesRef.current = nodes
  }, [nodes])

  useEffect(() => {
    edgesRef.current = edges
  }, [edges])

  useEffect(() => {
    fetchTopology()
  }, [fetchTopology])

  useEffect(() => {
    return () => {
      fetchAbortRef.current?.abort()
    }
  }, [])

  useEffect(() => {
    const close = () => setNodeContextMenu(null)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [])

  const runReachabilityAnalysis = async () => {
    if (analyzingReachability) return;
    setAnalyzingReachability(true);

    try {
      const res = await fetch('/api/dashboard/reachability');
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`)
      const reachDataRaw = await res.json();
      const reachData: any[] = Array.isArray(reachDataRaw) ? reachDataRaw : [];

      setEdges((prevEdges) => {
        const nextEdges = prevEdges.map(edge => {
          const edgeData = ((edge.data || {}) as Record<string, any>)
          const baseStyle = edgeData.__baseStyle || edge.style || { stroke: 'hsl(var(--border))', strokeWidth: 2 }
          const baseAnimated = typeof edgeData.__baseAnimated === 'boolean' ? edgeData.__baseAnimated : Boolean(edge.animated)
          const baseLabel = typeof edgeData.__baseLabel === 'string' ? edgeData.__baseLabel : (edge.label || '')
          const reach = reachData.find(r =>
            (r.source === edge.source && r.target === edge.target) ||
            (r.source === edge.target && r.target === edge.source)
          );

          if (!reach) {
            return {
              ...edge,
              animated: baseAnimated,
              style: baseStyle,
              markerEnd: undefined,
              label: baseLabel,
              data: {
                ...edgeData,
                __reachability: null,
              },
            };
          }

          const color = reach.status === 'success' ? '#10b981' : reach.status === 'warning' ? '#f59e0b' : '#ef4444';
          const nextStyle = { ...baseStyle, stroke: color, strokeWidth: 3 }
          const nextAnimated = reach.status === 'success'
          const nextLabel =
            typeof reach.message === 'string' && reach.message.length > 0
              ? reach.message
              : baseLabel

          return {
            ...edge,
            animated: nextAnimated,
            style: nextStyle,
            markerEnd: undefined,
            data: {
              ...edgeData,
              __reachability: {
                status: reach.status,
                message: reach.message || '',
                style: nextStyle,
                animated: nextAnimated,
                label: nextLabel,
              },
            },
            label: nextLabel
          };
        })
        edgesRef.current = nextEdges
        return nextEdges
      });
      setTopologyRevision((v) => v + 1)
    } catch (error) {
      console.error('Reachability analysis failed:', error);
    } finally {
      setAnalyzingReachability(false);
    }
  };

  if (loading) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-4 bg-background">
        <RefreshCcw className="w-8 h-8 animate-spin text-primary" />
        <div className="text-ui-xs font-medium uppercase tracking-wide animate-breathe">Initializing Hierarchical Topology</div>
      </div>
    )
  }

  if (error || nodes.length === 0) {
    const noNodes = !error && nodes.length === 0
    const emptyHint =
      noNodes && topologySource === 'batfish'
        ? 'Batfish topology is empty. Run Prepare once, then retry.'
        : noNodes
          ? 'No nodes detected'
          : null

    return (
      <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-3 bg-background">
        <AlertCircle className="w-12 h-12 text-rose-500/50" />
        <div className="text-ui-base font-semibold uppercase tracking-wide">{error || 'No nodes detected'}</div>
        {emptyHint && (
          <div className="text-ui-sm text-muted-foreground/90">{emptyHint}</div>
        )}
        <div className="mt-4 flex items-center gap-2">
          <button
            onClick={fetchTopology}
            className="px-4 py-2 bg-primary/10 border border-primary/20 rounded text-ui-xs font-semibold uppercase hover:bg-primary/20 transition-all flex items-center gap-2"
          >
            <RefreshCcw className="w-3 h-3" /> Retry Scan
          </button>
          {topologySource === 'batfish' ? (
            <button
              onClick={() => setTopologySource('pnetlab')}
              className="px-4 py-2 bg-orange-500/10 border border-orange-500/30 rounded text-ui-xs font-semibold uppercase hover:bg-orange-500/20 transition-all"
            >
              Switch to Lab Map
            </button>
          ) : (
            <button
              onClick={() => setTopologySource('batfish')}
              className="px-4 py-2 bg-amber-500/10 border border-amber-500/30 rounded text-ui-xs font-semibold uppercase hover:bg-amber-500/20 transition-all"
            >
              Switch to Batfish
            </button>
          )}
        </div>
      </div>
    )
  }

  return (
    <div ref={panelRef} className="flex-1 h-full relative group">
      {/* === Unified control panel (toolbar + viz overlay) === */}
      <div className="absolute top-4 left-4 z-20 flex flex-col gap-2 max-w-sm">
        {/* Row 1: Toolbar (always visible) */}
        <div className="flex items-center gap-1.5 bg-card rounded-xl border border-border-subtle shadow-elevation-2 p-1.5">
          {/* Source Toggle */}
          <div className="flex bg-muted/50 rounded-lg p-0.5">
            <button
              onClick={() => setTopologySource('batfish')}
              className={`px-2.5 py-1 text-ui-xs font-semibold rounded transition-all flex items-center gap-1 ${
                topologySource === 'batfish'
                  ? 'bg-primary text-primary-foreground shadow-sm'
                  : 'hover:bg-muted text-muted-foreground'
              }`}
              title="Auto-layout from Batfish analysis"
            >
              <FlaskConical className="w-3 h-3" /> Batfish
            </button>
            <button
              onClick={() => setTopologySource('pnetlab')}
              className={`px-2.5 py-1 text-ui-xs font-semibold rounded transition-all flex items-center gap-1 ${
                topologySource === 'pnetlab'
                  ? 'bg-primary text-primary-foreground shadow-sm'
                  : 'hover:bg-muted text-muted-foreground'
              }`}
              title="Real positions from PNETLab"
            >
              <TestTube2 className="w-3 h-3" /> Lab
            </button>
          </div>

          {/* Layer Toggle (Batfish only) */}
          {topologySource === 'batfish' && (
            <div className="flex bg-muted/50 rounded-lg p-0.5">
              <button
                onClick={() => setLayer('l1')}
                className={`px-2 py-1 text-ui-xs font-semibold rounded transition-all flex items-center gap-1 ${
                  layer === 'l1'
                    ? 'bg-card text-foreground shadow-sm'
                    : 'hover:bg-muted text-muted-foreground'
                }`}
              >
                <Layers className="w-3 h-3" /> L1
              </button>
              <button
                onClick={() => setLayer('l3')}
                className={`px-2 py-1 text-ui-xs font-semibold rounded transition-all flex items-center gap-1 ${
                  layer === 'l3'
                    ? 'bg-card text-foreground shadow-sm'
                    : 'hover:bg-muted text-muted-foreground'
                }`}
              >
                <Network className="w-3 h-3" /> L3
              </button>
            </div>
          )}

          {/* Refresh */}
          <button
            onClick={fetchTopology}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            title="Refresh Topology"
          >
            <RefreshCcw className="w-3.5 h-3.5" />
          </button>

          {/* Divider */}
          <div className="w-px h-5 bg-border" />

          {/* Reachability */}
          <button
            onClick={runReachabilityAnalysis}
            disabled={analyzingReachability}
            className={`px-2.5 py-1 rounded-lg text-ui-xs font-semibold transition-all flex items-center gap-1 ${
              analyzingReachability
                ? 'text-muted-foreground cursor-not-allowed'
                : 'text-emerald-500 hover:bg-emerald-500/10 active:scale-95'
            }`}
          >
            <Zap className={`w-3 h-3 ${analyzingReachability ? 'animate-spin' : ''}`} />
            {analyzingReachability ? 'Analyzing...' : 'Reachability'}
          </button>
        </div>

      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        defaultEdgeOptions={{ type: 'default' }}
        onPaneClick={() => setNodeContextMenu(null)}
        onNodeClick={(_, node) => {
          setNodeContextMenu(null)
          setSelectedNode(node.id)
          if (!String(node.id).startsWith('net:')) {
            setChatContextDevice(toChatContext(node))
          }
        }}
        onNodeContextMenu={(event, node) => {
          event.preventDefault()
          event.stopPropagation()
          setSelectedNode(node.id)
          if (!String(node.id).startsWith('net:')) {
            setChatContextDevice(toChatContext(node))
          }
          const panelRect = panelRef.current?.getBoundingClientRect()
          const x = panelRect ? Math.max(8, event.clientX - panelRect.left) : event.clientX
          const y = panelRect ? Math.max(8, event.clientY - panelRect.top) : event.clientY
          setNodeContextMenu({
            nodeId: String(node.id),
            nodeType: String(node.type || 'device'),
            x,
            y,
          })
        }}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        colorMode={theme}
        className="bg-background"
        minZoom={0.05}
        maxZoom={2}
      >
        <Background variant={BackgroundVariant.Lines} gap={32} color={theme === 'dark' ? '#1a2030' : '#d0d4db'} />
        <Controls
          className="bg-card border-border shadow-2xl scale-90 origin-bottom-left"
        />
      </ReactFlow>

      {nodeContextMenu && (
        <div
          className="absolute z-30 min-w-[180px] rounded-xl border border-border-subtle bg-surface-raised shadow-elevation-3 p-1.5"
          style={{ left: nodeContextMenu.x, top: nodeContextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="px-2 py-1.5 text-ui-xs uppercase tracking-wide text-muted-foreground">
            {nodeContextMenu.nodeId}
          </div>
          <button
            onClick={() => {
              if (!String(nodeContextMenu.nodeId).startsWith('net:')) {
                openDetail('device', nodeContextMenu.nodeId)
              }
              setNodeContextMenu(null)
            }}
            disabled={String(nodeContextMenu.nodeId).startsWith('net:')}
            className="w-full text-left px-2.5 py-2 rounded-lg text-sm text-foreground hover:bg-muted/60 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Detail
          </button>
          <button
            onClick={() => {
              const nodeHit = nodesRef.current.find((n) => String(n.id) === nodeContextMenu.nodeId)
              if (nodeHit && !String(nodeHit.id).startsWith('net:')) {
                setChatContextDevice(toChatContext(nodeHit))
              }
              setNodeContextMenu(null)
            }}
            className="w-full text-left px-2.5 py-2 rounded-lg text-sm text-foreground hover:bg-muted/60 transition-colors"
          >
            Use As Chat Context
          </button>
        </div>
      )}

      {/* Legend / Status Overlay */}
      <div className="absolute bottom-6 right-6 p-4 bg-surface-raised/90 border border-border-subtle rounded-xl shadow-elevation-2 pointer-events-none select-none z-10">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${layer === 'l1' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]'}`} />
            <span className="text-ui-xs font-semibold uppercase tracking-wide text-foreground/80">
              {layer === 'l1' ? 'L1 Physical Path' : 'L3 Logical Path'}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full border border-border bg-muted/50" />
            <span className="text-ui-xs font-semibold uppercase tracking-wide text-muted-foreground">Inactive / Standby</span>
          </div>
        </div>
      </div>
    </div>
  )
}
