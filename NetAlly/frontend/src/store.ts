import { create } from 'zustand'

export interface Evidence {
  id: string
  type: string
  status: 'success' | 'warning' | 'error' | 'info'
  title: string
  summary: string
  timestamp: string
  details?: any
}

interface AppState {
  selectedNode: string | null
  setSelectedNode: (node: string | null) => void
  
  evidenceList: Evidence[]
  addEvidence: (evidence: Omit<Evidence, 'id' | 'timestamp'>) => void
  clearEvidence: () => void
  
  detailView: {
    isOpen: boolean
    type: 'node' | 'evidence' | 'device' | null
    id: string | null
  }
  openDetail: (type: 'node' | 'evidence' | 'device', id: string) => void
  closeDetail: () => void

  // New UI States
  theme: 'light' | 'dark'
  setTheme: (theme: 'light' | 'dark') => void
  
  language: 'en' | 'ko'
  setLanguage: (language: 'en' | 'ko') => void
  
  chatWidth: number
  setChatWidth: (width: number) => void
  
  settings: {
    showTopologyLabels: boolean
    autoOnboard: boolean
  }
  updateSettings: (settings: Partial<AppState['settings']>) => void

  // Dashboard & View Modes
  viewMode: 'dashboard' | 'topology'
  setViewMode: (mode: 'dashboard' | 'topology') => void
  
  // Topology Source Selection
  topologySource: 'batfish' | 'pnetlab'
  setTopologySource: (source: 'batfish' | 'pnetlab') => void
}

export const useAppStore = create<AppState>((set) => ({
  selectedNode: null,
  setSelectedNode: (node) => set({ selectedNode: node }),
  
  evidenceList: [],
  addEvidence: (evidence) => set((state) => ({
    evidenceList: [
      {
        ...evidence,
        id: Math.random().toString(36).substring(7),
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      },
      ...state.evidenceList
    ].slice(0, 50)
  })),
  clearEvidence: () => set({ evidenceList: [] }),
  
  detailView: {
    isOpen: false,
    type: null,
    id: null
  },
  openDetail: (type, id) => set({
    detailView: { isOpen: true, type, id }
  }),
  closeDetail: () => set({
    detailView: { isOpen: false, type: null, id: null }
  }),

  theme: 'dark',
  setTheme: (theme) => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('theme', theme)
    set({ theme })
  },
  
  language: (localStorage.getItem('language') as 'en' | 'ko') || 'en',
  setLanguage: (language) => {
    localStorage.setItem('language', language)
    set({ language })
  },
  
  chatWidth: 450,
  setChatWidth: (width) => set({ chatWidth: Math.max(300, Math.min(width, 800)) }),
  
  settings: {
    showTopologyLabels: true,
    autoOnboard: false,
  },
  updateSettings: (newSettings) => set((state) => ({
    settings: { ...state.settings, ...newSettings }
  })),

  viewMode: 'dashboard',
  setViewMode: (mode) => set({ viewMode: mode }),
  
  topologySource: (localStorage.getItem('topologySource') as 'batfish' | 'pnetlab') || 'batfish',
  setTopologySource: (source) => {
    localStorage.setItem('topologySource', source)
    set({ topologySource: source })
  },
}))
