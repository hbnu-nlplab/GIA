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
    oobIntf: string
    deviceGroup: string
    pnetlabVmIp: string
    gatewayIp: string
    nsoAuthgroup: string
    nsoNedId: string
  }
  updateSettings: (settings: Partial<AppState['settings']>) => void

  // Dashboard & View Modes
  viewMode: 'dashboard' | 'topology'
  setViewMode: (mode: 'dashboard' | 'topology') => void
  
  // Topology Source Selection
  topologySource: 'batfish' | 'pnetlab'
  setTopologySource: (source: 'batfish' | 'pnetlab') => void

  // Lab Operations Status
  labPrepareStatus: string | null
  labPrepareDetail: any | null
  setLabPrepare: (status: string | null, detail?: any) => void

  labRefreshResult: any | null
  setLabRefreshResult: (result: any | null) => void
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
    oobIntf: localStorage.getItem('lab_oob_intf') || '',
    deviceGroup: localStorage.getItem('lab_device_group') || '',
    pnetlabVmIp: localStorage.getItem('lab_pnetlab_vm_ip') || '',
    gatewayIp: localStorage.getItem('lab_gateway_ip') || '',
    nsoAuthgroup: localStorage.getItem('lab_nso_authgroup') || '',
    nsoNedId: localStorage.getItem('lab_nso_ned_id') || '',
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

  labPrepareStatus: null,
  labPrepareDetail: null,
  setLabPrepare: (status, detail) => set({ labPrepareStatus: status, labPrepareDetail: detail ?? null }),

  labRefreshResult: null,
  setLabRefreshResult: (result) => set({ labRefreshResult: result }),
}))

// persist lab settings
const persistLabSettings = (settings: AppState['settings']) => {
  localStorage.setItem('lab_oob_intf', settings.oobIntf || '')
  localStorage.setItem('lab_device_group', settings.deviceGroup || '')
  localStorage.setItem('lab_pnetlab_vm_ip', settings.pnetlabVmIp || '')
  localStorage.setItem('lab_gateway_ip', settings.gatewayIp || '')
  localStorage.setItem('lab_nso_authgroup', settings.nsoAuthgroup || '')
  localStorage.setItem('lab_nso_ned_id', settings.nsoNedId || '')
}

useAppStore.subscribe((state, prev) => {
  if (state.settings !== prev.settings) {
    persistLabSettings(state.settings)
  }
})
