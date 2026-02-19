import { useState, useEffect, useRef } from 'react'
import { ReactFlowProvider } from '@xyflow/react'
import Header from './components/Header'
import TopologyPanel from './components/TopologyPanel'
import DashboardPanel from './components/DashboardPanel'
import ChatPanel from './components/ChatPanel'
import EvidencePanel from './components/EvidencePanel'
import DeviceDetailPanel from './components/DeviceDetailPanel'
import { DeviceInspectorContent, EvidenceInspectorContent } from './components/InspectorPanels'
import { useAppStore } from './store'

function App() {
  const { 
    selectedNode, 
    detailView, 
    closeDetail, 
    theme, 
    chatWidth, 
    setChatWidth,
    viewMode,
    setViewMode
  } = useAppStore((state) => ({
    selectedNode: state.selectedNode,
    detailView: state.detailView,
    closeDetail: state.closeDetail,
    theme: state.theme,
    chatWidth: state.chatWidth,
    setChatWidth: state.setChatWidth,
    viewMode: state.viewMode,
    setViewMode: state.setViewMode
  }))

  const [localShowEvidence, setLocalShowEvidence] = useState(true)
  const isResizing = useRef(false)

  // Ensure theme class is consistent with store on mount
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
  }, [theme])

  // Resizer logic
  const startResizing = (e: React.MouseEvent) => {
    e.preventDefault()
    isResizing.current = true
    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', stopResizing)
    document.body.style.cursor = 'col-resize'
  }

  const handleMouseMove = (e: MouseEvent) => {
    if (!isResizing.current) return
    const newWidth = window.innerWidth - e.clientX
    setChatWidth(newWidth)
  }

  const stopResizing = () => {
    isResizing.current = false
    document.removeEventListener('mousemove', handleMouseMove)
    document.removeEventListener('mouseup', stopResizing)
    document.body.style.cursor = 'default'
  }

  return (
    <ReactFlowProvider>
      <div className={`flex flex-col h-screen bg-background text-foreground transition-colors duration-300 font-sans overflow-hidden selection:bg-blue-500/30`}>
        <Header />

        <main className="flex-1 flex overflow-hidden relative">
          {/* Main View Area (Topology or Dashboard) */}
          <div className="flex-1 relative flex flex-col min-w-0">
            {viewMode === 'dashboard' ? <DashboardPanel /> : <TopologyPanel />}

            {/* View Mode Toggle Switch */}
            <div className="absolute top-4 left-1/2 -translate-x-1/2 flex bg-surface-raised border border-border-subtle p-1 rounded-lg shadow-elevation-2 z-10">
              <button
                onClick={() => setViewMode('dashboard')}
                className={`px-4 py-1.5 rounded-md text-ui-sm font-semibold transition-all flex items-center gap-2 ${
                  viewMode === 'dashboard' ? 'bg-primary text-primary-foreground shadow-sm' : 'hover:bg-muted text-muted-foreground'
                }`}
              >
                Dashboard
              </button>
              <button
                onClick={() => setViewMode('topology')}
                className={`px-4 py-1.5 rounded-md text-ui-sm font-semibold transition-all flex items-center gap-2 ${
                  viewMode === 'topology' ? 'bg-primary text-primary-foreground shadow-sm' : 'hover:bg-muted text-muted-foreground'
                }`}
              >
                Map View
              </button>
            </div>
            
            {/* Overlay Evidence Dashboard (Toggleable) */}
            {localShowEvidence && (
              <div className="absolute top-4 right-4 w-80 max-h-[calc(100%-2rem)] z-10 transition-all duration-300">
                <EvidencePanel onClose={() => setLocalShowEvidence(false)} />
              </div>
            )}
            
            {!localShowEvidence && (
              <button 
                onClick={() => setLocalShowEvidence(true)}
                className="absolute top-4 right-4 z-10 h-10 w-10 bg-surface-raised border border-border-subtle rounded-lg flex items-center justify-center hover:bg-accent transition-all shadow-elevation-2 hover:scale-110 active:scale-95 text-xl"
                title="Show Evidence"
              >
                📊
              </button>
            )}
            
            {/* Detail Slide-over */}
            {detailView.isOpen && (
              <div className="absolute inset-y-0 left-0 w-[400px] bg-card border-r border-border z-30 shadow-elevation-3 animate-in slide-in-from-left duration-300">
                <div className="flex flex-col h-full">
                   <div className="p-6 border-b border-border flex justify-between items-center">
                     <div>
                       <h2 className="text-ui-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">
                          {detailView.type === 'node' ? 'Device Inspector' : 'Evidence Logs'}
                       </h2>
                       <div className="text-xl font-medium text-foreground tracking-tight">
                        {detailView.id}
                       </div>
                     </div>
                     <button 
                       onClick={closeDetail} 
                       className="h-8 w-8 flex items-center justify-center rounded-full hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                     >
                       ✕
                     </button>
                   </div>
                   <div className="flex-1 overflow-auto p-6">
                      {detailView.type === 'node' && detailView.id ? (
                        <DeviceInspectorContent deviceId={detailView.id} />
                      ) : detailView.type === 'evidence' && detailView.id ? (
                        <EvidenceInspectorContent evidenceId={detailView.id} />
                      ) : (
                        <p className="text-xs text-muted-foreground">No data available</p>
                      )}
                   </div>
                </div>
              </div>
            )}
          </div>

          {/* Resizer Handle */}
          <div 
            onMouseDown={startResizing}
            className="w-1.5 h-full cursor-col-resize hover:bg-primary/40 active:bg-primary transition-colors flex items-center justify-center group z-40 bg-border/20"
          >
            <div className="w-0.5 h-8 bg-border group-hover:bg-primary/60 rounded-full" />
          </div>

          {/* Right: Interaction (Chat) */}
          <div 
            className="flex flex-col bg-card shadow-elevation-3 z-20"
            style={{ width: `${chatWidth}px` }}
          >
            <ChatPanel selectedNode={selectedNode} />
          </div>
        </main>
        
        {/* Device Detail Panel (slides in from right) */}
        <DeviceDetailPanel />
      </div>
    </ReactFlowProvider>
  )
}

export default App
