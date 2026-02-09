import { Sun, Moon, Languages, X } from 'lucide-react'
import { useAppStore } from '../store'
import { useTranslation } from '../i18n'
import { useEffect, useState } from 'react'

type ApiSettingsSnapshot = {
  nsoBaseUrl: string
  nsoUsername: string
  pnetlabUrl: string
  batfishHost: string
  toolBackend: 'mcp' | 'legacy'
  mcpServerUrl: string
  mcpAllowMutations: boolean
}

const DEFAULT_API_SNAPSHOT: ApiSettingsSnapshot = {
  nsoBaseUrl: '',
  nsoUsername: '',
  pnetlabUrl: '',
  batfishHost: '',
  toolBackend: 'mcp',
  mcpServerUrl: '',
  mcpAllowMutations: false,
}

export default function SettingsDialog({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) {
  const { theme, setTheme, language, setLanguage, settings, updateSettings } = useAppStore()
  const { t } = useTranslation()
  const [pnetlabCookies, setPnetlabCookies] = useState(localStorage.getItem('pnetlab_cookies') || '')
  const [pnetlabUser, setPnetlabUser] = useState(localStorage.getItem('pnetlab_user') || '')
  const [pnetlabPass, setPnetlabPass] = useState(localStorage.getItem('pnetlab_pass') || '')
  const [autoLogin, setAutoLogin] = useState(localStorage.getItem('pnetlab_auto_login') === 'true')
  const [authStatus, setAuthStatus] = useState<'unknown' | 'ok' | 'fail'>('unknown')

  // API Connections state
  const [openaiKey, setOpenaiKey] = useState('')
  const [nsoBaseUrl, setNsoBaseUrl] = useState('')
  const [nsoUsername, setNsoUsername] = useState('')
  const [nsoPassword, setNsoPassword] = useState('')
  const [pnetlabUrl, setPnetlabUrl] = useState('')
  const [batfishHost, setBatfishHost] = useState('')
  const [toolBackend, setToolBackend] = useState<'mcp' | 'legacy'>('mcp')
  const [mcpServerUrl, setMcpServerUrl] = useState('')
  const [mcpAllowMutations, setMcpAllowMutations] = useState(false)
  const [initialApiSettings, setInitialApiSettings] = useState<ApiSettingsSnapshot>(DEFAULT_API_SNAPSHOT)
  const [apiStatus, setApiStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [apiError, setApiError] = useState('')

  useEffect(() => {
    if (!isOpen) return
    const fetchStatus = async () => {
      try {
        const res = await fetch('/api/pnetlab/status')
        const data = await res.json()
        setAuthStatus(data?.authenticated ? 'ok' : 'fail')
      } catch {
        setAuthStatus('fail')
      }
    }
    // Fetch current API settings
    const fetchSettings = async () => {
      try {
        const res = await fetch('/api/settings')
        const data = await res.json()
        const snapshot: ApiSettingsSnapshot = {
          nsoBaseUrl: data.nso_base_url || '',
          nsoUsername: data.nso_username || '',
          pnetlabUrl: data.pnetlab_url || '',
          batfishHost: data.batfish_host || '',
          toolBackend: data.tool_backend === 'legacy' ? 'legacy' : 'mcp',
          mcpServerUrl: data.mcp_server_url || '',
          mcpAllowMutations: Boolean(data.mcp_allow_mutations),
        }

        setNsoBaseUrl(snapshot.nsoBaseUrl)
        setNsoUsername(snapshot.nsoUsername)
        setPnetlabUrl(snapshot.pnetlabUrl)
        setBatfishHost(snapshot.batfishHost)
        setToolBackend(snapshot.toolBackend)
        setMcpServerUrl(snapshot.mcpServerUrl)
        setMcpAllowMutations(snapshot.mcpAllowMutations)
        setInitialApiSettings(snapshot)
        setApiError('')
      } catch {
        // ignore
      }
    }
    fetchStatus()
    fetchSettings()
  }, [isOpen])

  if (!isOpen) return null

  const applyAuth = async () => {
    localStorage.setItem('pnetlab_cookies', pnetlabCookies)
    localStorage.setItem('pnetlab_user', pnetlabUser)
    localStorage.setItem('pnetlab_pass', pnetlabPass)
    localStorage.setItem('pnetlab_auto_login', autoLogin ? 'true' : 'false')
    try {
      const res = await fetch('/api/pnetlab/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cookies: pnetlabCookies || null,
          username: pnetlabUser || null,
          password: pnetlabPass || null,
          auto_login: autoLogin
        })
      })
      const data = await res.json()
      setAuthStatus(data?.authenticated ? 'ok' : 'fail')
    } catch {
      setAuthStatus('fail')
    }
  }

  const applyApiSettings = async () => {
    setApiStatus('saving')
    setApiError('')
    try {
      const payload: Record<string, string | boolean> = {}
      if (openaiKey.trim()) payload.openai_api_key = openaiKey.trim()
      if (nsoBaseUrl !== initialApiSettings.nsoBaseUrl) payload.nso_base_url = nsoBaseUrl
      if (nsoUsername !== initialApiSettings.nsoUsername) payload.nso_username = nsoUsername
      if (nsoPassword.trim()) payload.nso_password = nsoPassword.trim()
      if (pnetlabUrl !== initialApiSettings.pnetlabUrl) payload.pnetlab_url = pnetlabUrl
      if (batfishHost !== initialApiSettings.batfishHost) payload.batfish_host = batfishHost
      if (toolBackend !== initialApiSettings.toolBackend) payload.tool_backend = toolBackend
      if (mcpServerUrl !== initialApiSettings.mcpServerUrl) payload.mcp_server_url = mcpServerUrl
      if (mcpAllowMutations !== initialApiSettings.mcpAllowMutations) {
        payload.mcp_allow_mutations = mcpAllowMutations
      }

      if (Object.keys(payload).length === 0) {
        setApiStatus('saved')
        setTimeout(() => setApiStatus('idle'), 1500)
        return
      }

      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      if (res.ok) {
        setInitialApiSettings({
          nsoBaseUrl,
          nsoUsername,
          pnetlabUrl,
          batfishHost,
          toolBackend,
          mcpServerUrl,
          mcpAllowMutations,
        })
        setApiStatus('saved')
        setTimeout(() => setApiStatus('idle'), 2000)
      } else {
        const errBody = await res.json().catch(() => null)
        let message = 'Failed to update settings.'
        if (res.status === 422 && errBody?.detail) {
          if (Array.isArray(errBody.detail) && errBody.detail.length > 0) {
            message = String(errBody.detail[0]?.msg || message)
          } else if (typeof errBody.detail === 'string') {
            message = errBody.detail
          }
        } else if (errBody?.detail) {
          message = String(errBody.detail)
        }
        setApiError(message)
        setApiStatus('error')
      }
    } catch {
      setApiError('Network error while saving settings.')
      setApiStatus('error')
    }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        className="w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200"
        onClick={e => e.stopPropagation()}
      >
        <div className="px-6 py-4 border-b border-border flex justify-between items-center bg-muted/20">
          <h2 className="text-sm font-bold uppercase tracking-widest text-muted-foreground">System Settings</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Theme Section */}
          <section className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-tighter text-primary/80 flex items-center gap-2">
              <Sun className="w-3 h-3" />
              {t('settings.theme')}
            </label>
            <div className="flex gap-2 p-1 bg-muted/30 rounded-lg">
              <button
                onClick={() => setTheme('light')}
                className={`flex-1 flex items-center justify-center gap-2 py-2 text-xs font-bold rounded-md transition-all ${theme === 'light' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
              >
                <Sun className="w-4 h-4" />
                {t('settings.light')}
              </button>
              <button
                onClick={() => setTheme('dark')}
                className={`flex-1 flex items-center justify-center gap-2 py-2 text-xs font-bold rounded-md transition-all ${theme === 'dark' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
              >
                <Moon className="w-4 h-4" />
                {t('settings.dark')}
              </button>
            </div>
          </section>

          {/* Language Section */}
          <section className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-tighter text-primary/80 flex items-center gap-2">
              <Languages className="w-3 h-3" />
              {t('settings.language')}
            </label>
            <div className="flex gap-2 p-1 bg-muted/30 rounded-lg">
              <button
                onClick={() => setLanguage('en')}
                className={`flex-1 py-2 text-xs font-bold rounded-md transition-all ${language === 'en' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
              >
                English
              </button>
              <button
                onClick={() => setLanguage('ko')}
                className={`flex-1 py-2 text-xs font-bold rounded-md transition-all ${language === 'ko' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
              >
                한국어
              </button>
            </div>
          </section>

          {/* Behavior Section */}
          <section className="space-y-4">
            <h3 className="text-[10px] font-black uppercase tracking-tighter text-primary/80">Laboratory Behavior</h3>

            <div className="flex items-center justify-between group">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-foreground">Topology Labels</div>
                <div className="text-[10px] text-muted-foreground">Show device names and IP addresses by default.</div>
              </div>
              <input
                type="checkbox"
                checked={settings.showTopologyLabels}
                onChange={e => updateSettings({ showTopologyLabels: e.target.checked })}
                className="w-4 h-4 rounded border-border text-primary focus:ring-primary accent-primary"
              />
            </div>

            <div className="flex items-center justify-between group">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-foreground">Auto-Onboarding</div>
                <div className="text-[10px] text-muted-foreground">Automatically register new PNETLab nodes to NSO.</div>
              </div>
              <input
                type="checkbox"
                checked={settings.autoOnboard}
                onChange={e => updateSettings({ autoOnboard: e.target.checked })}
                className="w-4 h-4 rounded border-border text-primary focus:ring-primary accent-primary"
              />
            </div>
          </section>

          <section className="space-y-3">
            <h3 className="text-[10px] font-black uppercase tracking-tighter text-primary/80">Bootstrap Overrides</h3>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">OOB Interface (optional)</label>
              <input
                value={settings.oobIntf}
                onChange={e => updateSettings({ oobIntf: e.target.value })}
                placeholder="GigabitEthernet0/2"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">Device Group (optional)</label>
              <input
                value={settings.deviceGroup}
                onChange={e => updateSettings({ deviceGroup: e.target.value })}
                placeholder="RI_Internal_DC"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">PNETLab VM IP (optional)</label>
              <input
                value={settings.pnetlabVmIp}
                onChange={e => updateSettings({ pnetlabVmIp: e.target.value })}
                placeholder="100.66.240.82"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">Gateway IP (optional)</label>
              <input
                value={settings.gatewayIp}
                onChange={e => updateSettings({ gatewayIp: e.target.value })}
                placeholder="10.10.10.1"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">NSO Authgroup (optional)</label>
              <input
                value={settings.nsoAuthgroup}
                onChange={e => updateSettings({ nsoAuthgroup: e.target.value })}
                placeholder="default"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">NSO NED ID (optional)</label>
              <input
                value={settings.nsoNedId}
                onChange={e => updateSettings({ nsoNedId: e.target.value })}
                placeholder="cisco-ios-cli-6.110"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
          </section>

          {/* API Connections */}
          <section className="space-y-3">
            <h3 className="text-[10px] font-black uppercase tracking-tighter text-primary/80">
              API Connections
              {apiStatus === 'saved' && <span className="ml-2 text-emerald-500">✓ Saved</span>}
              {apiStatus === 'error' && <span className="ml-2 text-rose-500">Error</span>}
            </h3>
            {apiError && (
              <div className="text-[10px] text-rose-500 bg-rose-500/10 border border-rose-500/30 rounded-md px-2 py-1">
                {apiError}
              </div>
            )}
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">OpenAI API Key</label>
              <input
                type="password"
                value={openaiKey}
                onChange={e => setOpenaiKey(e.target.value)}
                placeholder="sk-..."
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">NSO Base URL</label>
              <input
                value={nsoBaseUrl}
                onChange={e => setNsoBaseUrl(e.target.value)}
                placeholder="http://10.10.10.100:8080/restconf"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-2">
                <label className="text-[10px] text-muted-foreground uppercase tracking-widest">NSO Username</label>
                <input
                  value={nsoUsername}
                  onChange={e => setNsoUsername(e.target.value)}
                  placeholder="admin"
                  className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
                />
              </div>
              <div className="space-y-2">
                <label className="text-[10px] text-muted-foreground uppercase tracking-widest">NSO Password</label>
                <input
                  type="password"
                  value={nsoPassword}
                  onChange={e => setNsoPassword(e.target.value)}
                  placeholder="admin"
                  className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
                />
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">PNETLab URL</label>
              <input
                value={pnetlabUrl}
                onChange={e => setPnetlabUrl(e.target.value)}
                placeholder="http://192.168.50.60"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">Batfish Host</label>
              <input
                value={batfishHost}
                onChange={e => setBatfishHost(e.target.value)}
                placeholder="batfish (or localhost)"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">Tool Backend</label>
              <div className="flex gap-2 p-1 bg-muted/30 rounded-lg">
                <button
                  onClick={() => setToolBackend('mcp')}
                  className={`flex-1 py-2 text-xs font-bold rounded-md transition-all ${toolBackend === 'mcp' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
                >
                  MCP
                </button>
                <button
                  onClick={() => setToolBackend('legacy')}
                  className={`flex-1 py-2 text-xs font-bold rounded-md transition-all ${toolBackend === 'legacy' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
                >
                  Legacy
                </button>
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">MCP Server URL</label>
              <input
                value={mcpServerUrl}
                onChange={e => setMcpServerUrl(e.target.value)}
                placeholder="http://127.0.0.1:8811/mcp"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="flex items-center justify-between group">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-foreground">Allow MCP Mutations</div>
                <div className="text-[10px] text-muted-foreground">Enable only for explicit onboarding/sync changes.</div>
              </div>
              <input
                type="checkbox"
                checked={mcpAllowMutations}
                onChange={e => setMcpAllowMutations(e.target.checked)}
                className="w-4 h-4 rounded border-border text-primary focus:ring-primary accent-primary"
              />
            </div>
            <button
              onClick={applyApiSettings}
              disabled={apiStatus === 'saving'}
              className="w-full py-2 text-[11px] font-bold uppercase tracking-widest rounded-md bg-primary text-primary-foreground hover:scale-105 transition-all disabled:opacity-50"
            >
              {apiStatus === 'saving' ? 'Saving...' : 'Apply API Settings'}
            </button>
          </section>

          <section className="space-y-3">
            <h3 className="text-[10px] font-black uppercase tracking-tighter text-primary/80">PNETLab Auth</h3>
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Status</span>
              <span className={`${authStatus === 'ok' ? 'text-emerald-500' : authStatus === 'fail' ? 'text-rose-500' : 'text-slate-500'}`}>
                {authStatus === 'ok' ? 'Authenticated' : authStatus === 'fail' ? 'Not Authenticated' : 'Unknown'}
              </span>
            </div>
            <div className="flex items-center justify-between group">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-foreground">Auto Login</div>
                <div className="text-[10px] text-muted-foreground">Use username/password if cookies are not set.</div>
              </div>
              <input
                type="checkbox"
                checked={autoLogin}
                onChange={e => setAutoLogin(e.target.checked)}
                className="w-4 h-4 rounded border-border text-primary focus:ring-primary accent-primary"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">Username</label>
              <input
                value={pnetlabUser}
                onChange={e => setPnetlabUser(e.target.value)}
                placeholder="admin"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">Password</label>
              <input
                type="password"
                value={pnetlabPass}
                onChange={e => setPnetlabPass(e.target.value)}
                placeholder="pnetlab"
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-muted-foreground uppercase tracking-widest">Cookies (fallback)</label>
              <textarea
                rows={3}
                value={pnetlabCookies}
                onChange={e => setPnetlabCookies(e.target.value)}
                placeholder="token=...; _session=...; XSRF-TOKEN=..."
                className="w-full px-3 py-2 text-xs rounded-md bg-muted/40 border border-border focus:outline-none focus:ring-1 focus:ring-primary/40"
              />
            </div>
            <button
              onClick={applyAuth}
              className="w-full py-2 text-[11px] font-bold uppercase tracking-widest rounded-md bg-primary text-primary-foreground hover:scale-105 transition-all"
            >
              Apply Auth
            </button>
          </section>

          <section className="pt-4 border-t border-border">
            <div className="bg-primary/5 p-3 rounded-lg border border-primary/20">
              <p className="text-[10px] text-primary/80 leading-relaxed italic">
                Settings are saved locally and applied in real-time. Cloud synchronization is currently disabled.
              </p>
            </div>
          </section>
        </div>

        <div className="px-6 py-4 bg-muted/10 border-t border-border flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-primary text-primary-foreground text-[11px] font-bold rounded-lg hover:scale-105 transition-all shadow-lg active:scale-95 uppercase tracking-widest"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  )
}
