import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  Node,
  Edge,
  useNodesState,
  useEdgesState,
  MarkerType,
} from '@xyflow/react'
import { Zap, RefreshCcw, AlertCircle, Layers, Network } from 'lucide-react'
import DeviceNode from './DeviceNode'
import NetworkNode from './NetworkNode'
import { useAppStore } from '../store'
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

const nodeTypes: Record<string, any> = {
  device: DeviceNode,
  network: NetworkNode,
}

const getLayoutedElements = (nodes: Node[], edges: Edge[], direction = 'TB') => {
  const dagreGraph = new dagre.graphlib.Graph()
  dagreGraph.setDefaultEdgeLabel(() => ({}))
  dagreGraph.setGraph({ rankdir: direction, nodesep: 150, ranksep: 200 })

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 220, height: 80 })
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target)
  });

  dagre.layout(dagreGraph)

  const newNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id)
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 110,
        y: nodeWithPosition.y - 40,
      },
    }
  })

  return { nodes: newNodes, edges }
}

export default function TopologyPanel() {
  const { setSelectedNode, openDetail, theme, topologySource, setTopologySource, viz } = useAppStore(state => ({
    setSelectedNode: state.setSelectedNode,
    openDetail: state.openDetail,
    theme: state.theme,
    topologySource: state.topologySource,
    setTopologySource: state.setTopologySource,
    viz: state.viz,
  }))

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [analyzingReachability, setAnalyzingReachability] = useState(false)
  const [layer, setLayer] = useState<'l1' | 'l3'>('l1')

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

  const vizNodeSet = useMemo(() => {
    if (!viz) return new Set<string>()
    return new Set((viz.nodes || []).map((n) => String(n).toLowerCase()))
  }, [viz])

  const vizEdgeSet = useMemo(() => {
    if (!viz) return new Set<string>()
    const s = new Set<string>()
    for (const e of viz.edges || []) {
      const src = String(e.source).toLowerCase()
      const tgt = String(e.target).toLowerCase()
      if (src && tgt) s.add(`${src}->${tgt}`)
    }
    return s
  }, [viz])

  const isEdgeInViz = useCallback((src: string, tgt: string) => {
    const a = `${String(src).toLowerCase()}->${String(tgt).toLowerCase()}`
    const b = `${String(tgt).toLowerCase()}->${String(src).toLowerCase()}`
    return vizEdgeSet.has(a) || vizEdgeSet.has(b)
  }, [vizEdgeSet])

  const baseEdgeMarkerColor = theme === 'dark' ? '#10b981' : '#059669'
  const vizEdgeColor = viz?.mode === 'path' ? (theme === 'dark' ? '#34d399' : '#059669') : (theme === 'dark' ? '#fb923c' : '#f97316')

  const fetchTopology = useCallback(async () => {
    let switchingSource = false
    setLoading(true)
    setError(null)
    try {
      // API 선택: Batfish vs PNETLab
      const apiUrl = topologySource === 'pnetlab' 
        ? '/api/topology/pnetlab'
        : `/api/topology?layer=${layer}`
      
      const res = await fetch(apiUrl)
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`)
      const data = await res.json()

      if (!data || !Array.isArray(data.nodes)) {
        throw new Error('Invalid topology data format')
      }

      // If Batfish returns no nodes and the user hasn't explicitly chosen a
      // source yet, auto-switch to PNETLab to avoid a confusing "Map view broken"
      // first impression.
      if (
        topologySource === 'batfish' &&
        !hasPersistedTopologySource &&
        Array.isArray(data.nodes) &&
        data.nodes.length === 0
      ) {
        switchingSource = true
        setTopologySource('pnetlab')
        return
      }

      // PNETLab 응답에 position이 있는지 확인
      const hasPositions = data.nodes.some((n: any) => n.position?.x !== undefined)

      const flowNodes: Node[] = data.nodes.map((n: ApiNode & { position?: { x: number, y: number } }) => ({
        id: n.id,
        type: n.type === 'network' ? 'network' : 'device',
        // PNETLab 위치가 있으면 직접 사용, 없으면 (0,0)으로 시작
        position: hasPositions && n.position 
          ? { x: n.position.x, y: n.position.y }
          : { x: 0, y: 0 },
        data: { 
          label: n.id, 
          platform: n.data?.platform || 'Unknown',
          device_type: n.data?.device_type || 'router',
          highlight: vizNodeSet.has(String(n.id).toLowerCase()),
          highlightMode: viz?.mode || 'focus',
          ...n.data 
        },
      }))

      const flowEdges: Edge[] = (data.edges || []).map((e: ApiEdge, i: number) => ({
        id: `e-${e.source}-${e.target}-${i}`,
        source: e.source,
        target: e.target,
        label: e.label,
        animated: true,
        markerEnd: { 
          type: MarkerType.ArrowClosed,
          color: isEdgeInViz(e.source, e.target) ? vizEdgeColor : baseEdgeMarkerColor
        },
        style: isEdgeInViz(e.source, e.target)
          ? { stroke: vizEdgeColor, strokeWidth: 4 }
          : { stroke: 'hsl(var(--border))', strokeWidth: 2, ...(e.style || {}) },
        labelStyle: { fill: 'hsl(var(--muted-foreground))', fontSize: 10, fontWeight: 600 },
        labelBgStyle: { fill: 'hsl(var(--card))', fillOpacity: 0.8 },
        labelBgPadding: [4, 2],
        labelBgBorderRadius: 4,
      }))

      // PNETLab 위치가 있으면 dagre 건너뛰기
      if (hasPositions) {
        setNodes(flowNodes)
        setEdges(flowEdges)
      } else {
        const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(flowNodes, flowEdges)
        setNodes(layoutedNodes)
        setEdges(layoutedEdges)
      }
    } catch (err: any) {
      console.error('Failed to fetch topology:', err)
      setError(err.message || 'Failed to load topology')
    } finally {
      if (!switchingSource) setLoading(false)
    }
  }, [theme, layer, topologySource, setNodes, setEdges, viz, vizNodeSet, isEdgeInViz, vizEdgeColor, baseEdgeMarkerColor, hasPersistedTopologySource, setTopologySource])

  // Apply visualization overlay to existing nodes/edges whenever viz changes.
  useEffect(() => {
    setNodes((prev) => prev.map((n) => ({
      ...n,
      data: {
        ...(n.data || {}),
        highlight: vizNodeSet.has(String(n.id).toLowerCase()),
        highlightMode: viz?.mode || 'focus',
      },
    })))

    setEdges((prev) => prev.map((e) => {
      const highlighted = viz ? isEdgeInViz(e.source, e.target) : false
      return {
        ...e,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: highlighted ? vizEdgeColor : baseEdgeMarkerColor,
        },
        style: highlighted ? { stroke: vizEdgeColor, strokeWidth: 4 } : { stroke: 'hsl(var(--border))', strokeWidth: 2 },
      }
    }))
  }, [viz, vizNodeSet, isEdgeInViz, setNodes, setEdges, vizEdgeColor, baseEdgeMarkerColor])

  useEffect(() => {
    fetchTopology()
  }, [fetchTopology])

  const runReachabilityAnalysis = async () => {
    if (analyzingReachability) return;
    setAnalyzingReachability(true);

    try {
      const res = await fetch('/api/dashboard/reachability');
      const reachData: any[] = await res.json();

      setEdges((prevEdges) => prevEdges.map(edge => {
        const reach = reachData.find(r => 
          (r.source === edge.source && r.target === edge.target) ||
          (r.source === edge.target && r.target === edge.source)
        );
        
        if (reach) {
          const color = reach.status === 'success' ? '#10b981' : reach.status === 'warning' ? '#f59e0b' : '#ef4444';
          return {
            ...edge,
            animated: reach.status === 'success',
            style: { ...edge.style, stroke: color, strokeWidth: 3 },
            label: reach.message || edge.label
          };
        }
        return edge;
      }));
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
        <div className="text-[10px] font-bold uppercase tracking-widest animate-pulse">Initializing Hierarchical Topology</div>
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
        <div className="text-xs font-bold uppercase tracking-[0.2em]">{error || 'No nodes detected'}</div>
        {emptyHint && (
          <div className="text-[11px] text-muted-foreground/90">{emptyHint}</div>
        )}
        <div className="mt-4 flex items-center gap-2">
          <button
            onClick={fetchTopology}
            className="px-4 py-2 bg-primary/10 border border-primary/20 rounded text-[10px] font-bold uppercase hover:bg-primary/20 transition-all flex items-center gap-2"
          >
            <RefreshCcw className="w-3 h-3" /> Retry Scan
          </button>
          {topologySource === 'batfish' ? (
            <button
              onClick={() => setTopologySource('pnetlab')}
              className="px-4 py-2 bg-orange-500/10 border border-orange-500/30 rounded text-[10px] font-bold uppercase hover:bg-orange-500/20 transition-all"
            >
              Switch to Lab Map
            </button>
          ) : (
            <button
              onClick={() => setTopologySource('batfish')}
              className="px-4 py-2 bg-amber-500/10 border border-amber-500/30 rounded text-[10px] font-bold uppercase hover:bg-amber-500/20 transition-all"
            >
              Switch to Batfish
            </button>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 h-full relative group">
      {/* Topology Toolbar */}
      <div className="absolute top-4 right-4 z-20 flex flex-col gap-2">
        <div className="flex gap-2">
          {/* Layer Toggle (L1/L3) - only show for Batfish */}
          {topologySource === 'batfish' && (
            <div className="flex bg-card p-1 rounded-lg border border-border shadow-lg">
              <button
                onClick={() => setLayer('l1')}
                className={`px-3 py-1 text-[10px] font-bold uppercase rounded transition-all flex items-center gap-1.5 ${
                  layer === 'l1' ? 'bg-primary text-primary-foreground shadow-sm' : 'hover:bg-muted text-muted-foreground'
                }`}
              >
                <Layers className="w-3 h-3" /> Physical
              </button>
              <button
                onClick={() => setLayer('l3')}
                className={`px-3 py-1 text-[10px] font-bold uppercase rounded transition-all flex items-center gap-1.5 ${
                  layer === 'l3' ? 'bg-blue-500 text-white shadow-sm' : 'hover:bg-muted text-muted-foreground'
                }`}
              >
                <Network className="w-3 h-3" /> Logical
              </button>
            </div>
          )}
          
          {/* Source Toggle (Batfish/PNETLab) */}
          <div className="flex bg-card p-1 rounded-lg border border-border shadow-lg">
            <button
              onClick={() => setTopologySource('batfish')}
              className={`px-3 py-1 text-[10px] font-bold uppercase rounded transition-all flex items-center gap-1.5 ${
                topologySource === 'batfish' ? 'bg-amber-500 text-white shadow-sm' : 'hover:bg-muted text-muted-foreground'
              }`}
              title="Auto-layout from Batfish analysis"
            >
              🔬 Batfish
            </button>
            <button
              onClick={() => setTopologySource('pnetlab')}
              className={`px-3 py-1 text-[10px] font-bold uppercase rounded transition-all flex items-center gap-1.5 ${
                topologySource === 'pnetlab' ? 'bg-orange-500 text-white shadow-sm' : 'hover:bg-muted text-muted-foreground'
              }`}
              title="Real positions from PNETLab"
            >
              🧪 Lab
            </button>
          </div>
          
          <button
            onClick={fetchTopology}
            className="px-3 py-1.5 rounded-lg border bg-card text-foreground border-border text-xs font-bold shadow-lg hover:bg-muted transition-all active:scale-95 flex items-center gap-1.5"
            title="Refresh Topology"
          >
            <RefreshCcw className="w-3.5 h-3.5" />
          </button>
        </div>

        <button
          onClick={runReachabilityAnalysis}
          disabled={analyzingReachability}
          className={`
            w-full px-3 py-1.5 rounded-lg border text-xs font-bold shadow-lg transition-all
            ${analyzingReachability 
              ? 'bg-muted text-muted-foreground cursor-not-allowed' 
              : 'bg-emerald-500 text-white border-emerald-600 hover:bg-emerald-600 active:scale-95'
            }
            flex items-center justify-center gap-1.5
          `}
        >
          <Zap className={`w-3.5 h-3.5 ${analyzingReachability ? 'animate-spin' : ''}`} />
          {analyzingReachability ? 'Analyzing...' : 'Reachability Analysis'}
        </button>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={(_, node) => {
          setSelectedNode(node.id)
          openDetail('device', node.id)
        }}
        nodeTypes={nodeTypes}
        fitView
        colorMode={theme}
        className="bg-background"
        minZoom={0.05}
        maxZoom={2}
      >
        <Background gap={32} size={1} color={theme === 'dark' ? '#222' : '#eee'} />
        <Controls
          className="bg-card border-border shadow-2xl scale-90 origin-bottom-left"
        />
      </ReactFlow>
      
      {/* Legend / Status Overlay */}
      <div className="absolute bottom-6 right-6 p-4 bg-card/60 backdrop-blur-md border border-border rounded-xl shadow-2xl pointer-events-none select-none z-10">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${layer === 'l1' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]'}`} />
            <span className="text-[10px] font-bold uppercase tracking-widest text-foreground/80">
              {layer === 'l1' ? 'L1 Physical Path' : 'L3 Logical Path'}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full border border-border bg-muted/50" />
            <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Inactive / Standby</span>
          </div>
        </div>
      </div>
    </div>
  )
}
