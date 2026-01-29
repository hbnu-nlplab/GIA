import { useCallback, useEffect, useState } from 'react'
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
import DeviceNode from './DeviceNode'
import { useAppStore } from '../store'

interface ApiNode {
  id: string
  type: string
  data: Record<string, unknown>
  position?: { x: number, y: number }
}

interface ApiEdge {
  source: string
  target: string
  label?: string
}

const nodeTypes: Record<string, any> = {
  device: DeviceNode,
}

const initialNodes: Node[] = []
const initialEdges: Edge[] = []

export default function TopologyPanel() {
  const { setSelectedNode, openDetail, theme } = useAppStore(state => ({
    setSelectedNode: state.setSelectedNode,
    openDetail: state.openDetail,
    theme: state.theme
  }))

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchTopology = async () => {
      setLoading(true)
      try {
        const res = await fetch('/api/topology')
        const data = await res.json()

        const flowNodes: Node[] = data.nodes.map((n: ApiNode, i: number) => ({
          id: n.id,
          type: 'device',
          position: n.position || { 
            x: 100 + (i % 4) * 220, 
            y: 100 + Math.floor(i / 4) * 180 
          },
          data: { 
            label: n.id, 
            type: n.type,
            ...n.data 
          },
        }))

        const flowEdges: Edge[] = data.edges.map((e: ApiEdge, i: number) => ({
          id: `e-${e.source}-${e.target}-${i}`,
          source: e.source,
          target: e.target,
          label: e.label,
          animated: true,
          markerEnd: { 
            type: MarkerType.ArrowClosed,
            color: '#10b981'
          },
          style: { stroke: 'hsl(var(--border))', strokeWidth: 2 },
          labelStyle: { fill: 'hsl(var(--muted-foreground))', fontSize: 10, fontWeight: 600 },
          labelBgStyle: { fill: 'hsl(var(--card))', fillOpacity: 0.8 },
          labelBgPadding: [4, 2],
          labelBgBorderRadius: 4,
        }))

        setNodes(flowNodes)
        setEdges(flowEdges)
      } catch (err) {
        console.error('Failed to fetch topology:', err)
      } finally {
        setLoading(false)
      }
    }

    fetchTopology()
  }, [setNodes, setEdges])

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node.id)
  }, [setSelectedNode])

  const onNodeDoubleClick = useCallback((_: React.MouseEvent, node: Node) => {
    openDetail('node', node.id)
  }, [openDetail])

  const onPaneClick = useCallback(() => {
    setSelectedNode(null)
  }, [setSelectedNode])

  if (loading) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-4 bg-background">
        <div className="h-1 w-32 bg-muted rounded-full overflow-hidden">
          <div className="h-full bg-primary animate-[loading_1.5s_infinite]" />
        </div>
        <div className="text-[10px] font-bold uppercase tracking-widest animate-pulse">Initializing Topology</div>
      </div>
    )
  }

  if (nodes.length === 0) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-3 bg-background">
        <div className="text-4xl opacity-20 grayscale">🕸️</div>
        <div className="text-xs font-bold uppercase tracking-[0.2em]">No topology detected</div>
        <button 
          onClick={() => window.location.reload()}
          className="mt-4 px-4 py-2 bg-primary/10 border border-primary/20 rounded text-[10px] font-bold uppercase hover:bg-primary/20 transition-all"
        >
          Retry Scan
        </button>
      </div>
    )
  }

  return (
    <div className="h-full relative font-sans bg-background">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onNodeDoubleClick={onNodeDoubleClick}
        onPaneClick={onPaneClick}
        nodeTypes={nodeTypes}
        fitView
        colorMode={theme}
        className="bg-background"
        minZoom={0.2}
        maxZoom={4}
      >
        <Background gap={24} size={1} />
        <Controls 
          className="bg-card border-border shadow-2xl scale-90 origin-bottom-left" 
        />
      </ReactFlow>
      
      {/* Legend / Status Overlay */}
      <div className="absolute bottom-6 right-6 p-4 bg-card/60 backdrop-blur-md border border-border rounded-xl shadow-2xl pointer-events-none select-none">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
            <span className="text-[10px] font-bold uppercase tracking-widest text-foreground/80">L3 Link Active</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-muted border border-border" />
            <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Peer Discovery</span>
          </div>
        </div>
      </div>
    </div>
  )
}

