import { useState, useEffect } from 'react'
import { Wifi, Shield, AlertTriangle, Cpu, RefreshCw, Play, Zap, Activity, TrendingUp, TrendingDown, Eye, Server, Lock, Clock } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area } from 'recharts'
import api, { API_URL } from '../lib/api'

const COLORS = {
  green: '#22c55e',
  red: '#ef4444', 
  yellow: '#f59e0b',
  blue: '#0ea5e9',
  purple: '#8b5cf6',
  cyan: '#06b6d4'
}

export default function Dashboard({ status, socket, onRefresh }) {
  const [scanning, setScanning] = useState(false)
  const [lastScan, setLastScan] = useState(null)
  const [scanHistory, setScanHistory] = useState([])
  const [authStatus, setAuthStatus] = useState(null)
  const [startupEvents, setStartupEvents] = useState([])

  useEffect(() => {
    const loadDashboardContext = async () => {
      try {
        const [authRes, eventsRes] = await Promise.all([
          api.get(`${API_URL}/api/v1/auth/verify`),
          api.get(`${API_URL}/api/v1/events/security?limit=20`),
        ])
        setAuthStatus(authRes.data)
        const relevant = (eventsRes.data.events || []).filter((event) =>
          [
            'dns_resolver_started',
            'dns_resolver_autostart_skipped',
            'dns_resolver_autostart_failed',
            'traffic_monitor_started',
            'traffic_monitor_start_failed',
          ].includes(event.event_type)
        )
        setStartupEvents(relevant)
      } catch (err) {
        setAuthStatus({ authenticated: false, enabled: true, role: null })
      }
    }

    const handleSecurityEvent = (event) => {
      const payload = event.detail
      if (!payload) return
      if (
        [
          'dns_resolver_started',
          'dns_resolver_autostart_skipped',
          'dns_resolver_autostart_failed',
          'traffic_monitor_started',
          'traffic_monitor_start_failed',
        ].includes(payload.event_type)
      ) {
        setStartupEvents((current) => [payload, ...current.filter((item) => item.id !== payload.id)].slice(0, 10))
      }
    }

    loadDashboardContext()
    window.addEventListener('sentinel:security-event', handleSecurityEvent)
    return () => window.removeEventListener('sentinel:security-event', handleSecurityEvent)
  }, [])

  const latestTrafficStartup = startupEvents.find((event) => event.event_type?.startsWith('traffic_monitor_'))
  const latestDnsStartup = startupEvents.find((event) => event.event_type?.startsWith('dns_resolver_'))

  const handleNetworkScan = async () => {
    if (scanning) return
    setScanning(true)
    try {
      await api.post(`${API_URL}/api/v1/scan/network`)
      setLastScan(new Date())
      onRefresh()
      setScanHistory(prev => [...prev.slice(-4), { time: new Date().toLocaleTimeString(), devices: (status.total_devices || 0) + 1 }])
    } catch (err) {
      console.error('Scan failed:', err)
    } finally {
      setScanning(false)
    }
  }

  const stats = [
    { 
      label: 'Total Devices', 
      value: status.total_devices || 0, 
      icon: Wifi, 
      color: COLORS.blue,
      bg: 'from-blue-500/20 to-blue-600/10',
      trend: '+12%',
      trendUp: true
    },
    { 
      label: 'Trusted Devices', 
      value: status.trusted_devices || 0, 
      icon: Shield, 
      color: COLORS.green,
      bg: 'from-green-500/20 to-green-600/10',
      trend: '+3',
      trendUp: true
    },
    { 
      label: 'High Risk', 
      value: status.high_risk_devices || 0, 
      icon: AlertTriangle, 
      color: COLORS.red,
      bg: 'from-red-500/20 to-red-600/10',
      trend: status.high_risk_devices > 0 ? 'Action needed' : 'Clear',
      trendUp: status.high_risk_devices === 0
    },
    { 
      label: 'Active Alerts', 
      value: status.active_alerts || 0, 
      icon: Activity, 
      color: COLORS.yellow,
      bg: 'from-yellow-500/20 to-yellow-600/10',
      trend: '-2',
      trendUp: false
    },
  ]

  const riskData = [
    { name: 'Low Risk', value: Math.max(0, (status.total_devices || 0) - (status.high_risk_devices || 0) - (status.medium_risk_devices || 0)), color: COLORS.green },
    { name: 'Medium Risk', value: status.medium_risk_devices || 0, color: COLORS.yellow },
    { name: 'High Risk', value: status.high_risk_devices || 0, color: COLORS.red },
  ].filter(d => d.value > 0)

  const activityData = [
    { time: '00:00', devices: 8, threats: 0 },
    { time: '04:00', devices: 6, threats: 1 },
    { time: '08:00', devices: 12, threats: 2 },
    { time: '12:00', devices: 15, threats: 1 },
    { time: '16:00', devices: 18, threats: 3 },
    { time: '20:00', devices: 14, threats: 1 },
    { time: 'Now', devices: status.total_devices || 0, threats: status.high_risk_devices || 0 },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-2xl font-bold text-white">Security Dashboard</h3>
          <p className="text-sm text-slate-400 mt-1">Real-time network threat assessment & monitoring</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={onRefresh}
            className="sentinel-btn bg-slate-800 hover:bg-slate-700 text-white flex items-center gap-2 border border-slate-700"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={handleNetworkScan}
            disabled={scanning}
            className="sentinel-btn sentinel-btn-primary flex items-center gap-2"
          >
            {scanning ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            {scanning ? 'Scanning...' : 'Network Scan'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat, idx) => (
          <div 
            key={idx} 
            className="stat-card group"
            style={{ '--accent': stat.color }}
          >
            <div className="flex items-start justify-between mb-4">
              <div className={`p-3 rounded-xl bg-gradient-to-br ${stat.bg} border border-slate-700/50`}>
                <stat.icon className="w-6 h-6" style={{ color: stat.color }} />
              </div>
              <div className={`flex items-center gap-1 text-xs font-medium ${
                stat.trendUp ? 'text-green-400' : 'text-red-400'
              }`}>
                {stat.trendUp ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                {stat.trend}
              </div>
            </div>
            <div className="text-3xl font-bold text-white mb-1">{stat.value}</div>
            <div className="text-sm text-slate-400">{stat.label}</div>
            <div 
              className="absolute bottom-0 left-0 right-0 h-1 rounded-b-xl opacity-50"
              style={{ background: `linear-gradient(90deg, ${stat.color}, transparent)` }}
            />
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 glass-panel p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h4 className="text-lg font-semibold text-white">Network Activity</h4>
              <p className="text-sm text-slate-400">Device discovery over time</p>
            </div>
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-cyan-500" />
                <span className="text-slate-400">Devices</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span className="text-slate-400">Threats</span>
              </div>
            </div>
          </div>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activityData}>
                <defs>
                  <linearGradient id="deviceGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLORS.cyan} stopOpacity={0.3}/>
                    <stop offset="95%" stopColor={COLORS.cyan} stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" fontSize={12} />
                <YAxis stroke="#475569" fontSize={12} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1e293b', 
                    border: '1px solid #334155',
                    borderRadius: '12px',
                    backdropFilter: 'blur(8px)'
                  }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
                <Area 
                  type="monotone" 
                  dataKey="devices" 
                  stroke={COLORS.cyan} 
                  fillOpacity={1} 
                  fill="url(#deviceGradient)" 
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel p-6">
          <h4 className="text-lg font-semibold text-white mb-6">Risk Distribution</h4>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData.length > 0 ? riskData : [{ name: 'No Data', value: 1, color: '#334155' }]}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {(riskData.length > 0 ? riskData : [{ color: '#334155' }]).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1e293b', 
                    border: '1px solid #334155',
                    borderRadius: '12px'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="space-y-2 mt-4">
            {riskData.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-300">{item.name}</span>
                </div>
                <span className="font-medium text-white">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Eye className="w-5 h-5 text-cyan-400" />
              <h4 className="text-lg font-semibold text-white">Quick Actions</h4>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <button 
              onClick={handleNetworkScan}
              disabled={scanning}
              className="p-4 rounded-xl bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 hover:border-cyan-500/40 transition-all group text-left"
            >
              <Wifi className="w-5 h-5 text-cyan-400 mb-2 group-hover:scale-110 transition-transform" />
              <div className="font-medium text-white">Scan Network</div>
              <div className="text-xs text-slate-400">Discover all devices</div>
            </button>
            <button className="p-4 rounded-xl bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/20 hover:border-purple-500/40 transition-all group text-left">
              <Server className="w-5 h-5 text-purple-400 mb-2 group-hover:scale-110 transition-transform" />
              <div className="font-medium text-white">View Devices</div>
              <div className="text-xs text-slate-400">{status.total_devices || 0} devices found</div>
            </button>
            <button className="p-4 rounded-xl bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/20 hover:border-red-500/40 transition-all group text-left">
              <Lock className="w-5 h-5 text-red-400 mb-2 group-hover:scale-110 transition-transform" />
              <div className="font-medium text-white">Auto Defense</div>
              <div className="text-xs text-slate-400">Block threats</div>
            </button>
            <button className="p-4 rounded-xl bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/20 hover:border-green-500/40 transition-all group text-left">
              <Clock className="w-5 h-5 text-green-400 mb-2 group-hover:scale-110 transition-transform" />
              <div className="font-medium text-white">Scan History</div>
              <div className="text-xs text-slate-400">{status.total_scans || 0} scans</div>
            </button>
          </div>
        </div>

        <div className="glass-panel p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Activity className="w-5 h-5 text-green-400" />
              <h4 className="text-lg font-semibold text-white">System Health</h4>
            </div>
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                <span className="text-slate-300">Database</span>
              </div>
              <span className="text-green-400 text-sm font-medium">Connected</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${status.llm_available ? 'bg-green-500 animate-pulse' : 'bg-yellow-500'}`} />
                <span className="text-slate-300">AI Model</span>
              </div>
              <span className={`${status.llm_available ? 'text-green-400' : 'text-yellow-400'} text-sm font-medium`}>
                {status.llm_available ? 'Phi-2 Ready' : 'Loading...'}
              </span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                <span className="text-slate-300">Network Scanner</span>
              </div>
              <span className="text-green-400 text-sm font-medium">Active</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${(authStatus?.authenticated || authStatus?.enabled === false) ? 'bg-green-500 animate-pulse' : 'bg-yellow-500'}`} />
                <span className="text-slate-300">Operator Role</span>
              </div>
              <span className={`${(authStatus?.authenticated || authStatus?.enabled === false) ? 'text-green-400' : 'text-yellow-400'} text-sm font-medium`}>
                {authStatus?.authenticated ? (authStatus.role || 'verified') : authStatus?.enabled === false ? 'Auth disabled' : 'Unverified'}
              </span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${socket?.current ? 'bg-green-500 animate-pulse' : 'bg-yellow-500'}`} />
                <span className="text-slate-300">Live Event Stream</span>
              </div>
              <span className={`${socket?.current ? 'text-green-400' : 'text-yellow-400'} text-sm font-medium`}>
                {socket?.current ? 'Connected' : 'Polling fallback'}
              </span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${latestTrafficStartup?.severity === 'warning' ? 'bg-yellow-500' : latestTrafficStartup ? 'bg-green-500 animate-pulse' : 'bg-slate-500'}`} />
                <span className="text-slate-300">Traffic Autostart</span>
              </div>
              <span className={`${latestTrafficStartup?.severity === 'warning' ? 'text-yellow-400' : latestTrafficStartup ? 'text-green-400' : 'text-slate-400'} text-sm font-medium`}>
                {latestTrafficStartup?.title || 'No startup event'}
              </span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50">
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${latestDnsStartup?.severity === 'warning' ? 'bg-yellow-500' : latestDnsStartup ? 'bg-green-500 animate-pulse' : 'bg-slate-500'}`} />
                <span className="text-slate-300">DNS Autostart</span>
              </div>
              <span className={`${latestDnsStartup?.severity === 'warning' ? 'text-yellow-400' : latestDnsStartup ? 'text-green-400' : 'text-slate-400'} text-sm font-medium`}>
                {latestDnsStartup?.title || 'No startup event'}
              </span>
            </div>
            {lastScan && (
              <div className="text-xs text-slate-500 text-center pt-2">
                Last scan: {lastScan.toLocaleString()}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

