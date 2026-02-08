import { Sun, Moon, Languages, X } from 'lucide-react'
import { useAppStore } from '../store'
import { useTranslation } from '../i18n'
import { useEffect, useState } from 'react'

export default function SettingsDialog({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) {
  const { theme, setTheme, language, setLanguage, settings, updateSettings } = useAppStore()
  const { t } = useTranslation()
  const [pnetlabCookies, setPnetlabCookies] = useState(localStorage.getItem('pnetlab_cookies') || '')
  const [pnetlabUser, setPnetlabUser] = useState(localStorage.getItem('pnetlab_user') || '')
  const [pnetlabPass, setPnetlabPass] = useState(localStorage.getItem('pnetlab_pass') || '')
  const [autoLogin, setAutoLogin] = useState(localStorage.getItem('pnetlab_auto_login') === 'true')
  const [authStatus, setAuthStatus] = useState<'unknown' | 'ok' | 'fail'>('unknown')

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
    fetchStatus()
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
