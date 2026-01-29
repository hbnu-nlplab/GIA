import { useAppStore } from '../store'

export default function SettingsDialog({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) {
  const { settings, updateSettings, theme, setTheme } = useAppStore(state => ({
    settings: state.settings,
    updateSettings: state.updateSettings,
    theme: state.theme,
    setTheme: state.setTheme
  }))

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        className="w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200"
        onClick={e => e.stopPropagation()}
      >
        <div className="px-6 py-4 border-b border-border flex justify-between items-center bg-muted/20">
          <h2 className="text-sm font-bold uppercase tracking-widest text-muted-foreground">System Settings</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 transition-colors">✕</button>
        </div>
        
        <div className="p-6 space-y-6">
          {/* Theme Section */}
          <section className="space-y-3">
            <h3 className="text-[10px] font-black uppercase tracking-tighter text-primary/80">Appearance</h3>
            <div className="flex gap-2 p-1 bg-muted/30 rounded-lg">
              <button 
                onClick={() => setTheme('light')}
                className={`flex-1 py-2 text-xs font-bold rounded-md transition-all ${theme === 'light' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
              >
                ☀️ Light
              </button>
              <button 
                onClick={() => setTheme('dark')}
                className={`flex-1 py-2 text-xs font-bold rounded-md transition-all ${theme === 'dark' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
              >
                🌙 Dark
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
