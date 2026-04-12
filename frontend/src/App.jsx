import { lazy, Suspense, useState, useEffect, useCallback, useRef } from 'react'
import { 
  Shield, Activity, Wifi, AlertTriangle, Command, Settings, Globe, Cpu, 
  Radio, Lock, FileText, Zap, ChevronRight, Menu, X, Bell, Search, Network, Bug
} from 'lucide-react'
import api, { API_URL, getWebSocketUrl } from './lib/api'

const Dashboard = lazy(() => import('./components/Dashboard'))
const Devices = lazy(() => import('./components/Devices'))
const NLPChat = lazy(() => import('./components/NLPChat'))
const Alerts = lazy(() => import('./components/Alerts'))
const SettingsPanel = lazy(() => import('./components/SettingsPanel'))
const MonitorPanel = lazy(() => import('./components/Monitor'))
const NetworkTopology = lazy(() => import('./components/Topology'))
const HoneypotPanel = lazy(() => import('./components/Honeypot'))

function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [status, setStatus] = useState({})
  const [wsConnected, setWsConnected] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const socketRef = useRef(null)
  const socketCleanupRef = useRef(false)
  const [loading, setLoading] = useState(true)
  const [currentTime, setCurrentTime] = useState(new Date())

  useEffect(() => {
    socketCleanupRef.current = false
    const ws = new WebSocket(getWebSocketUrl())

    ws.onopen = () => {
      if (socketCleanupRef.current) {
        ws.close()
        return
      }
      setWsConnected(true)
      socketRef.current = ws
    }

    ws.onclose = () => {
      if (socketCleanupRef.current) {
        return
      }
      setWsConnected(false)
      socketRef.current = null
    }

    ws.onmessage = (event) => {
      if (socketCleanupRef.current) {
        return
      }
      try {
        const message = JSON.parse(event.data)
        if (message?.type === 'security_event') {
          window.dispatchEvent(new CustomEvent('sentinel:security-event', { detail: message.payload }))
        } else if (message?.type === 'traffic_stats') {
          window.dispatchEvent(new CustomEvent('sentinel:traffic-stats', { detail: message.payload }))
        } else if (message?.type === 'defense_status') {
          window.dispatchEvent(new CustomEvent('sentinel:defense-status', { detail: message.payload }))
        } else if (message?.type === 'dns_stats') {
          window.dispatchEvent(new CustomEvent('sentinel:dns-stats', { detail: message.payload }))
        }
      } catch (error) {
        console.error('WebSocket message parse error:', error)
      }
    }

    ws.onerror = (error) => {
      if (socketCleanupRef.current || ws.readyState === WebSocket.CLOSING || ws.readyState === WebSocket.CLOSED) {
        return
      }
      console.error('WebSocket error:', error)
    }

    return () => {
      socketCleanupRef.current = true
      if (socketRef.current === ws) {
        socketRef.current = null
      }
      ws.close()
    }
  }, [])

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])

  const fetchStatus = useCallback(async () => {
    try {
      const res = await api.get(`${API_URL}/api/v1/status`)
      setStatus(res.data)
    } catch (err) {
      console.error('Failed to fetch status:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 10000)
    return () => clearInterval(interval)
  }, [fetchStatus])

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity, desc: 'Security overview & quick actions' },
    { id: 'topology', label: 'Topology', icon: Network, desc: 'Network map & device visualization' },
    { id: 'devices', label: 'Devices', icon: Wifi, desc: 'Network device management' },
    { id: 'monitor', label: 'Monitor', icon: Radio, desc: 'Real-time monitoring & controls' },
    { id: 'honeypot', label: 'Honeypot', icon: Bug, desc: 'Decoy services & attack capture' },
    { id: 'chat', label: 'AI Control', icon: Command, desc: 'Natural language security commands' },
    { id: 'alerts', label: 'Alerts', icon: Bell, desc: 'Security notifications & events' },
    { id: 'settings', label: 'Settings', icon: Settings, desc: 'System configuration' },
  ]

  const getStatusColor = () => {
    if (status.high_risk_devices > 0) return 'text-red-400'
    if (status.medium_risk_devices > 0) return 'text-yellow-400'
    return 'text-green-400'
  }

  const renderActivePanel = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard status={status} socket={socketRef} onRefresh={fetchStatus} />
      case 'topology':
        return <NetworkTopology />
      case 'devices':
        return <Devices />
      case 'monitor':
        return <MonitorPanel />
      case 'honeypot':
        return <HoneypotPanel />
      case 'chat':
        return <NLPChat />
      case 'alerts':
        return <Alerts />
      case 'settings':
        return <SettingsPanel />
      default:
        return <Dashboard status={status} socket={socketRef} onRefresh={fetchStatus} />
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0f1a] relative">
      <div className="fixed inset-0 bg-gradient-to-br from-slate-900 via-[#0a0f1a] to-slate-900 pointer-events-none" />
      
      <div className="flex relative z-10">
        <aside className={`${sidebarOpen ? 'w-72' : 'w-20'} bg-slate-900/95 backdrop-blur-xl border-r border-slate-800 flex flex-col transition-all duration-300`}>
          <div className="p-4 border-b border-slate-800">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/30">
                <Shield className="w-7 h-7 text-white" />
              </div>
              {sidebarOpen && (
                <div>
                  <h1 className="text-xl font-bold gradient-text">SENTINEL</h1>
                  <p className="text-xs text-slate-500">Security Platform</p>
                </div>
              )}
            </div>
          </div>

          <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
            {tabs.map(tab => (
              <li key={tab.id}>
                <button
                  onClick={() => setActiveTab(tab.id)}
                  className={`nav-item w-full ${activeTab === tab.id ? 'active' : 'text-slate-400 hover:text-white hover:bg-slate-800/50'}`}
                >
                  <tab.icon className={`w-5 h-5 ${activeTab === tab.id ? 'nav-icon' : ''}`} />
                  {sidebarOpen && (
                    <div className="flex-1 text-left">
                      <div className="font-medium">{tab.label}</div>
                      <div className="text-xs text-slate-500">{tab.desc}</div>
                    </div>
                  )}
                  {sidebarOpen && <ChevronRight className="w-4 h-4 text-slate-600" />}
                </button>
              </li>
            ))}
          </nav>

          <div className="p-4 border-t border-slate-800">
            <div className="glass-panel rounded-xl p-4">
              <div className="flex items-center gap-3 mb-3">
                <div className={`status-dot ${wsConnected ? 'status-online' : 'status-offline'}`} />
                <span className="text-sm text-slate-400">System Status</span>
              </div>
              {sidebarOpen && (
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Status</span>
                    <span className={wsConnected ? 'text-green-400' : 'text-red-400'}>
                      {wsConnected ? 'Online' : 'Offline'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">AI Model</span>
                    <span className={status.llm_available ? 'text-green-400' : 'text-slate-500'}>
                      {status.llm_available ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Time</span>
                    <span className="text-slate-300 font-mono">
                      {currentTime.toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </aside>

        <main className="flex-1 flex flex-col">
          <header className="bg-slate-900/80 backdrop-blur-xl border-b border-slate-800 px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-semibold text-white">
                  {tabs.find(t => t.id === activeTab)?.label}
                </h2>
                <p className="text-sm text-slate-400">Network Threat Intelligence & Defense</p>
              </div>
              
              <div className="flex items-center gap-4">
                <div className="relative">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Search..."
                    className="pl-10 pr-4 py-2 bg-slate-800/80 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:border-cyan-500 w-48"
                  />
                </div>
                
                <div className="flex items-center gap-3 px-4 py-2 glass-panel rounded-xl">
                  <Activity className={`w-5 h-5 ${getStatusColor()}`} />
                  <div>
                    <div className="text-xs text-slate-500">Security Status</div>
                    <div className={`text-sm font-medium ${getStatusColor()}`}>
                      {status.high_risk_devices > 0 
                        ? `${status.high_risk_devices} Critical Threats` 
                        : status.medium_risk_devices > 0
                          ? `${status.medium_risk_devices} Warnings`
                          : 'All Clear'}
                    </div>
                  </div>
                </div>
                
                <button 
                  onClick={() => setSidebarOpen(!sidebarOpen)}
                  className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
                >
                  <Menu className="w-5 h-5 text-slate-400" />
                </button>
              </div>
            </div>
          </header>

          <div className="flex-1 p-6 overflow-auto">
            <Suspense
              fallback={
                <div className="glass-panel rounded-xl p-8 text-center text-slate-400">
                  Loading panel...
                </div>
              }
            >
              {renderActivePanel()}
            </Suspense>
          </div>
        </main>
      </div>
    </div>
  )
}

export default App
