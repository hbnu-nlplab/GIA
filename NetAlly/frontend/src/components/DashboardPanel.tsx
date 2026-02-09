import React, { useEffect, useState } from 'react';
import {
  Activity,
  ShieldCheck,
  AlertTriangle,
  Zap,
  Maximize2,
  X
} from 'lucide-react';
import { useAppStore } from '../store';

interface ProtocolStatus {
  total: number;
  up: number;
  down: number;
  status: 'healthy' | 'warning' | 'critical' | 'unknown';
}

interface DashboardIssue {
  severity: 'critical' | 'warning';
  type: string;
  title: string;
  message: string;
  affected_nodes: string[];
}

interface DashboardData {
  health_score: number;
  mode: string;
  protocols: {
    bgp: ProtocolStatus;
    ospf: ProtocolStatus;
  };
  issues: DashboardIssue[];
  device_status: Record<string, string>;
  compliance: {
    routing: number;
    security: number;
  };
}

const DEFAULT_PROTOCOL: ProtocolStatus = {
  total: 0,
  up: 0,
  down: 0,
  status: 'unknown',
};

const normalizeDashboardData = (raw: any): DashboardData => {
  const protocols = raw?.protocols || {};
  const bgp = protocols.bgp || {};
  const ospf = protocols.ospf || {};
  const compliance = raw?.compliance || {};

  return {
    health_score: Number(raw?.health_score ?? 0),
    mode: String(raw?.mode ?? 'lab'),
    protocols: {
      bgp: {
        total: Number(bgp.total ?? DEFAULT_PROTOCOL.total),
        up: Number(bgp.up ?? DEFAULT_PROTOCOL.up),
        down: Number(bgp.down ?? DEFAULT_PROTOCOL.down),
        status: (bgp.status ?? DEFAULT_PROTOCOL.status) as ProtocolStatus['status'],
      },
      ospf: {
        total: Number(ospf.total ?? DEFAULT_PROTOCOL.total),
        up: Number(ospf.up ?? DEFAULT_PROTOCOL.up),
        down: Number(ospf.down ?? DEFAULT_PROTOCOL.down),
        status: (ospf.status ?? DEFAULT_PROTOCOL.status) as ProtocolStatus['status'],
      },
    },
    issues: Array.isArray(raw?.issues) ? raw.issues : [],
    device_status: raw?.device_status && typeof raw.device_status === 'object' ? raw.device_status : {},
    compliance: {
      routing: Number(compliance.routing ?? 0),
      security: Number(compliance.security ?? 0),
    },
  };
};

const DashboardPanel: React.FC = () => {
  // ALL HOOKS MUST BE AT THE TOP - BEFORE ANY CONDITIONAL RETURNS
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState<'lab' | 'production'>('lab');
  const [detailProtocol, setDetailProtocol] = useState<'bgp' | 'ospf' | null>(null);
  const [protocolData, setProtocolData] = useState<any[]>([]);
  const [showComplianceDetail, setShowComplianceDetail] = useState<'routing' | 'security' | 'insights' | null>(null);
  const [fetchingDetail, setFetchingDetail] = useState(false);
  
  const { setSelectedNode, labPrepareStatus, labPrepareDetail, labRefreshResult } = useAppStore();

  const fetchDashboard = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/dashboard/summary?mode=${mode}`);
      const result = await response.json();
      setData(normalizeDashboardData(result));
    } catch (error) {
      console.error('Failed to fetch dashboard summary:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchProtocolDetail = async (p: 'bgp' | 'ospf') => {
    try {
      setFetchingDetail(true);
      setDetailProtocol(p);
      const res = await fetch(`/api/dashboard/protocols/${p}`);
      const result = await res.json();
      setProtocolData(result);
    } catch (error) {
      console.error('Failed to fetch protocol details:', error);
    } finally {
      setFetchingDetail(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
    // Poll every 30 seconds
    const interval = setInterval(fetchDashboard, 30000);
    return () => clearInterval(interval);
  }, [mode]); // Refetch when mode changes

  // Early return AFTER all hooks
  if (loading && !data) {
    return (
      <div className="flex-1 flex items-center justify-center bg-background/50 backdrop-blur-sm">
        <div className="flex flex-col items-center gap-4">
          <Activity className="w-12 h-12 text-blue-500 animate-pulse" />
          <p className="text-muted-foreground animate-pulse">Analyzing network state...</p>
        </div>
      </div>
    );
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
      case 'warning': return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
      case 'critical': return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
      default: return 'text-slate-500 bg-slate-500/10 border-slate-500/20';
    }
  };

  const ProtocolDetailModal = () => {
    if (!detailProtocol) return null;

    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-md animate-in fade-in duration-200">
        <div className="w-full max-w-5xl max-h-[85vh] bg-card border border-border rounded-2xl shadow-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
          <div className="px-6 py-4 border-b border-border flex justify-between items-center bg-muted/20">
            <h3 className="font-bold uppercase tracking-widest text-base flex items-center gap-2">
              <Activity className="w-5 h-5 text-primary" />
              {detailProtocol.toUpperCase()} Session Details
            </h3>
            <button onClick={() => setDetailProtocol(null)} className="p-1 hover:bg-muted rounded-full transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="flex-1 overflow-auto p-0">
            {fetchingDetail ? (
              <div className="p-12 flex flex-col items-center justify-center gap-4">
                <Activity className="w-8 h-8 text-primary animate-spin" />
                <p className="text-sm text-muted-foreground uppercase tracking-widest">Fetching details...</p>
              </div>
            ) : protocolData.length === 0 ? (
              <div className="p-12 text-center text-muted-foreground uppercase text-xs font-bold tracking-widest">No detailed data available</div>
            ) : (
              <table className="w-full text-sm text-left border-collapse">
                <thead className="sticky top-0 bg-muted/50 backdrop-blur-sm shadow-sm border-b border-border">
                  <tr>
                    {Object.keys(protocolData[0]).slice(0, 6).map(key => (
                      <th key={key} className="px-4 py-3 font-bold uppercase tracking-wider text-xs text-muted-foreground whitespace-nowrap">{key.replace(/_/g, ' ')}</th>
                    ))}
                    <th className="px-4 py-3 font-bold uppercase tracking-wider text-xs text-muted-foreground whitespace-nowrap">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {protocolData.map((row, i) => (
                    <tr key={i} className="hover:bg-muted/30 transition-colors">
                      {Object.entries(row).slice(0, 6).map(([_k, v], j) => (
                        <td key={j} className="px-4 py-3 font-medium whitespace-nowrap">{String(v)}</td>
                      ))}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className={`px-2.5 py-1 rounded-full font-bold uppercase tracking-widest text-xs ${
                          String(Object.values(row).pop()).includes('ESTABLISHED') || String(Object.values(row).pop()).includes('COMPATIBLE')
                          ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20' 
                          : 'bg-rose-500/10 text-rose-500 border border-rose-500/20'
                        }`}>
                          {String(Object.values(row).pop())}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    );
  };

  const ComplianceDetailModal = () => {
    if (!showComplianceDetail) return null;

    const content = {
      routing: {
        title: "🛣️ Routing Hygiene",
        description: "Ensures that routing protocols are correctly configured and follow best practices.",
        checks: [
          { name: "MTU Consistency", desc: "All interfaces have matching MTU values to prevent fragmentation." },
          { name: "Router ID Uniqueness", desc: "Each router has a unique Router ID for OSPF and BGP." },
          { name: "OSPF Area Configuration", desc: "OSPF areas are correctly defined and backbone area (Area 0) exists." },
          { name: "Subnet Alignment", desc: "Interface IPs are properly aligned with routing announcements." }
        ]
      },
      security: {
        title: "🔒 Security Compliance",
        description: "Validates that security best practices are implemented across the network.",
        checks: [
          { name: "NTP Configuration", desc: "Network Time Protocol is configured for accurate logging." },
          { name: "SNMP Security", desc: "SNMPv3 is used or SNMPv2 communities are non-default." },
          { name: "AAA Authentication", desc: "Authentication, Authorization, and Accounting is enabled." },
          { name: "Strong Passwords", desc: "Enable secret and line passwords meet complexity requirements." }
        ]
      },
      insights: {
        title: "📊 Active Insights",
        description: "Real-time issues detected by Batfish deterministic analysis.",
        checks: [
          { name: "BGP Session Down", desc: "BGP peering sessions that are not in ESTABLISHED state." },
          { name: "OSPF Adjacency Issues", desc: "OSPF neighbors not in FULL state." },
          { name: "Unreachable Networks", desc: "Networks that cannot be reached from core routers." },
          { name: "Configuration Drift", desc: "Devices with configs that differ from intended baseline." }
        ]
      }
    };

    const current = content[showComplianceDetail];

    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-md animate-in fade-in duration-200">
        <div className="w-full max-w-3xl bg-card border border-border rounded-2xl shadow-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
          <div className="px-6 py-4 border-b border-border flex justify-between items-center bg-muted/20">
            <h3 className="font-bold text-lg flex items-center gap-2">
              {current.title}
            </h3>
            <button onClick={() => setShowComplianceDetail(null)} className="p-1 hover:bg-muted rounded-full transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="p-6 space-y-4">
            <p className="text-sm text-muted-foreground">{current.description}</p>
            <div className="space-y-3">
              <h4 className="font-semibold text-sm uppercase tracking-wider">Verification Checks:</h4>
              {current.checks.map((check, i) => (
                <div key={i} className="flex gap-3 p-3 bg-muted/30 rounded-lg">
                  <ShieldCheck className="w-5 h-5 text-emerald-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <div className="font-medium text-sm">{check.name}</div>
                    <div className="text-xs text-muted-foreground mt-0.5">{check.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="flex-1 flex flex-col p-8 overflow-y-auto custom-scrollbar">
      <ComplianceDetailModal />
      <ProtocolDetailModal />

      {/* Header Summary with Mode Toggle */}
      <div className="flex items-center justify-between bg-card p-6 rounded-2xl border border-border shadow-sm">
        <div className="space-y-1">
          <h2 className="text-2xl font-bold flex items-center gap-2">
            Network Health
            <ShieldCheck className="w-6 h-6 text-emerald-500" />
          </h2>
          <p className="text-muted-foreground">General verification status for Research_Institute_Internal_DC</p>
        </div>
        <div className="flex items-center gap-6">
          {/* Verification Mode Toggle */}
          <div className="flex bg-muted/30 p-1 rounded-lg border border-border">
            <button
              onClick={() => setMode('lab')}
              className={`px-3 py-1.5 rounded text-xs font-bold transition-all ${
                mode === 'lab' ? 'bg-blue-500 text-white shadow-sm' : 'hover:bg-muted/50 text-muted-foreground'
              }`}
            >
              🧪 Lab
            </button>
            <button
              onClick={() => setMode('production')}
              className={`px-3 py-1.5 rounded text-xs font-bold transition-all ${
                mode === 'production' ? 'bg-orange-500 text-white shadow-sm' : 'hover:bg-muted/50 text-muted-foreground'
              }`}
            >
              🏢 Production
            </button>
          </div>
          <div className="text-right">
            <p className="text-sm text-muted-foreground font-medium uppercase tracking-wider">Health Score</p>
            <p className={`text-4xl font-black ${data?.health_score && data.health_score > 80 ? 'text-emerald-500' : 'text-amber-500'}`}>
              {data?.health_score ?? 0}%
            </p>
          </div>
          <button
            onClick={fetchDashboard}
            className="p-2 hover:bg-muted rounded-full transition-colors"
            title="Refresh Analysis"
          >
            <Zap className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Lab Operations Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl border bg-card/60 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-lg">Batfish Prepare</h3>
            <span className={`text-[10px] uppercase font-black tracking-[0.2em] px-2 py-1 rounded-md ${
              labPrepareStatus === 'ready' || labPrepareStatus === 'loaded' || labPrepareStatus === 'initialized'
                ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
                : labPrepareStatus === 'not_ready'
                ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20'
                : 'bg-slate-500/10 text-slate-500 border border-slate-500/20'
            }`}>
              {labPrepareStatus || 'unknown'}
            </span>
          </div>
          <div className="text-xs text-muted-foreground">
            {labPrepareDetail?.snapshot && (
              <div>Snapshot: <span className="text-foreground">{labPrepareDetail.snapshot}</span></div>
            )}
            {!labPrepareDetail && <div>Click “Prepare” in the header to check Batfish readiness.</div>}
          </div>
        </div>

        <div className="p-6 rounded-2xl border bg-card/60 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-lg">Refresh Result</h3>
            <span className="text-[10px] uppercase font-black tracking-[0.2em] px-2 py-1 rounded-md bg-muted/40 text-muted-foreground">
              {labRefreshResult?.status || 'idle'}
            </span>
          </div>
          {labRefreshResult ? (
            <div className="space-y-2 text-xs">
              <div className="text-muted-foreground">
                New devices: <span className="text-foreground">{labRefreshResult?.missing?.length || 0}</span>
              </div>
              <div className="text-muted-foreground">
                SSH 실패: <span className="text-foreground">{Object.entries(labRefreshResult?.ssh || {}).filter(([, ok]) => !ok).length}</span>
              </div>
              <div className="text-muted-foreground">
                NSO 등록 실패: <span className="text-foreground">{labRefreshResult?.nso?.failed?.length || 0}</span>
              </div>
              {labRefreshResult?.nso?.failed?.length ? (
                <div className="text-[10px] text-rose-500/80">
                  Failed: {labRefreshResult.nso.failed.join(', ')}
                </div>
              ) : null}
            </div>
          ) : (
            <div className="text-xs text-muted-foreground">Click “Refresh” to bootstrap new devices.</div>
          )}
        </div>
      </div>

      {/* Protocol Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* BGP Card */}
        <div 
          onClick={() => fetchProtocolDetail('bgp')}
          className={`cursor-pointer group relative p-6 bg-card rounded-2xl border transition-all hover:shadow-xl hover:-translate-y-1 ${getStatusColor(data?.protocols.bgp.status || 'unknown')}`}
        >
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-background/50 rounded-lg group-hover:scale-110 transition-transform">
                <Activity className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-lg">BGP Status</h3>
            </div>
            <span className="text-[10px] uppercase font-black tracking-[0.2em] px-2 py-1 bg-background/50 rounded-md">
              {data?.protocols.bgp.status}
            </span>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-3 bg-background/40 rounded-xl">
              <div className="text-2xl font-black mb-1">{data?.protocols.bgp.total}</div>
              <div className="text-[9px] uppercase font-bold text-muted-foreground">Total</div>
            </div>
            <div className="text-center p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/10">
              <div className="text-2xl font-black text-emerald-500 mb-1">{data?.protocols.bgp.up}</div>
              <div className="text-[9px] uppercase font-bold text-emerald-500/80">Established</div>
            </div>
            <div className="text-center p-3 bg-rose-500/10 rounded-xl border border-rose-500/10">
              <div className="text-2xl font-black text-rose-500 mb-1">{data?.protocols.bgp.down}</div>
              <div className="text-[9px] uppercase font-bold text-rose-500/80">Down</div>
            </div>
          </div>
          <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
            <Maximize2 className="w-4 h-4 text-muted-foreground/50" />
          </div>
        </div>

        {/* OSPF Card */}
        <div 
          onClick={() => fetchProtocolDetail('ospf')}
          className={`cursor-pointer group relative p-6 bg-card rounded-2xl border transition-all hover:shadow-xl hover:-translate-y-1 ${getStatusColor(data?.protocols.ospf.status || 'unknown')}`}
        >
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-background/50 rounded-lg group-hover:scale-110 transition-transform">
                <Activity className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-lg">OSPF Status</h3>
            </div>
            <span className="text-[10px] uppercase font-black tracking-[0.2em] px-2 py-1 bg-background/50 rounded-md">
              {data?.protocols.ospf.status}
            </span>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-3 bg-background/40 rounded-xl">
              <div className="text-2xl font-black mb-1">{data?.protocols.ospf.total}</div>
              <div className="text-[9px] uppercase font-bold text-muted-foreground">Total</div>
            </div>
            <div className="text-center p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/10">
              <div className="text-2xl font-black text-emerald-500 mb-1">{data?.protocols.ospf.up}</div>
              <div className="text-[9px] uppercase font-bold text-emerald-500/80">Full/Comp</div>
            </div>
            <div className="text-center p-3 bg-rose-500/10 rounded-xl border border-rose-500/10">
              <div className="text-2xl font-black text-rose-500 mb-1">{data?.protocols.ospf.down}</div>
              <div className="text-[9px] uppercase font-bold text-rose-500/80">Issue</div>
            </div>
          </div>
          <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
            <Maximize2 className="w-4 h-4 text-muted-foreground/50" />
          </div>
        </div>
      </div>

      {/* Compliance Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Routing Compliance */}
        <div 
          onClick={() => setShowComplianceDetail('routing')}
          className="cursor-pointer group p-6 rounded-2xl border bg-card/50 backdrop-blur-sm hover:bg-accent/50 transition-all hover:shadow-lg"
        >
          <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
            🛣️ Routing Hygiene
            <span className="text-xs bg-muted px-2 py-0.5 rounded-lg text-muted-foreground">
              Always Checked
            </span>
            <Maximize2 className="w-3 h-3 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
          </h3>
          <div className="text-center">
            <p className="text-3xl font-bold text-emerald-500">{data?.compliance?.routing ?? 100}%</p>
            <p className="text-xs text-muted-foreground mt-1">MTU, Router ID, OSPF Area</p>
          </div>
        </div>

        {/* Security Compliance */}
        <div 
          onClick={() => mode === 'production' && setShowComplianceDetail('security')}
          className={`p-6 rounded-2xl border bg-card/50 backdrop-blur-sm ${
            mode === 'production' ? 'cursor-pointer group hover:bg-accent/50 transition-all hover:shadow-lg' : 'opacity-50 cursor-not-allowed'
          }`}
        >
          <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
            🔒 Security Compliance
            <span className="text-xs bg-muted px-2 py-0.5 rounded-lg text-muted-foreground">
              {mode === 'production' ? 'Active' : 'Disabled (Lab Mode)'}
            </span>
            {mode === 'production' && <Maximize2 className="w-3 h-3 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />}
          </h3>
          <div className="text-center">
            <p className="text-3xl font-bold text-blue-500">
              {mode === 'production' ? `${data?.compliance?.security ?? 100}%` : 'N/A'}
            </p>
            <p className="text-xs text-muted-foreground mt-1">NTP, SNMP, AAA, Passwords</p>
          </div>
        </div>
      </div>

      {/* Active Insights */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-bold text-lg flex items-center gap-2">
            Active Insights
            <span className="text-xs bg-muted px-2 py-0.5 rounded-lg text-muted-foreground">
              {data?.issues.length || 0}
            </span>
          </h3>
          <button 
            onClick={() => setShowComplianceDetail('insights')}
            className="text-xs text-primary hover:underline flex items-center gap-1"
          >
            <AlertTriangle className="w-3 h-3" /> What is this?
          </button>
        </div>
        {data?.issues.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-12 bg-card rounded-2xl border border-dashed border-border text-muted-foreground">
            <div className="w-12 h-12 rounded-full bg-emerald-500/10 flex items-center justify-center mb-4 text-emerald-500">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <p className="font-medium">No active issues detected. Great job!</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {data?.issues.map((issue, idx) => (
              <div 
                key={idx} 
                className={`flex gap-4 p-4 rounded-xl border bg-card/80 transition-all hover:translate-x-1 ${
                  issue.severity === 'critical' ? 'border-rose-500/30' : 'border-amber-500/30'
                }`}
              >
                <div className={`mt-0.5 p-2 h-fit rounded-lg shrink-0 ${
                  issue.severity === 'critical' ? 'text-rose-500 bg-rose-500/10' : 'text-amber-500 bg-amber-500/10'
                }`}>
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <h4 className="font-semibold text-sm">{issue.title}</h4>
                    <span className="text-[10px] text-muted-foreground uppercase">{issue.type}</span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed mb-3">
                    {issue.message}
                  </p>
                  
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => setSelectedNode(issue.affected_nodes[0] || null)}
                      className="text-[11px] font-bold text-blue-500 hover:underline flex items-center gap-1"
                    >
                      <Maximize2 className="w-3 h-3" /> View Device
                    </button>
                    <button
                      onClick={() => {
                        window.dispatchEvent(new CustomEvent('ask-agent', {
                          detail: { message: `Fix this issue: ${issue.title}. ${issue.message}` }
                        }));
                      }}
                      className="text-[11px] font-bold text-emerald-500 hover:underline flex items-center gap-1"
                    >
                      <Zap className="w-3 h-3" /> Ask Agent
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Call to action footer */}
      <div className="pt-4 border-t border-border mt-auto">
        <p className="text-xs text-muted-foreground flex items-center gap-2">
          <Activity className="w-3 h-3 text-blue-500" />
          Powered by Batfish Deterministic Analysis Agent v0.2
        </p>
      </div>
    </div>
  );
};

export default DashboardPanel;
