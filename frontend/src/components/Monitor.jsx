import { useState, useEffect } from 'react'
import { Activity, Play, Square, FileText, Network, AlertTriangle, RefreshCw, Info, Shield, Lock, Unlock, Globe, Zap, Brain, Bug, Trash2 } from 'lucide-react'
import api, { API_URL } from '../lib/api'

const SUSPICIOUS_PORTS = [
  { port: 23, name: 'Telnet', reason: 'Unencrypted remote access, often brute forced' },
  { port: 135, name: 'RPC', reason: 'Windows RPC, frequent target for exploits' },
  { port: 139, name: 'NetBIOS', reason: 'SMB over NetBIOS, internal recon' },
  { port: 445, name: 'SMB', reason: 'EternalBlue, ransomware target' },
  { port: 3389, name: 'RDP', reason: 'BlueKeep, brute force target' },
  { port: 4444, name: 'Metasploit', reason: 'Commonly used by malware' },
  { port: 5554, name: 'Sasser', reason: 'Worm backdoor' },
  { port: 8080, name: 'HTTP-Proxy', reason: 'Admin interfaces, proxy' },
  { port: 8888, name: 'HTTP-Alt', reason: 'Backdoor, trojan ports' },
]

const QUARANTINE_PROFILE_LABELS = {
  restricted_network: 'Restricted network',
  segment_isolation: 'Segment isolation',
  full_isolation: 'Full isolation',
  critical_service_isolation: 'Critical services only',
  defensive_lockdown: 'Defensive lockdown',
}

const formatDecisionTrace = (trace) => (Array.isArray(trace) ? trace : [])
  .map((entry) => entry?.detail || `${entry?.stage || 'decision'} -> ${entry?.outcome || 'unknown'}`)
  .filter(Boolean)

export default function Monitor() {
  const [trafficStats, setTrafficStats] = useState(null)
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [autoScanEnabled, setAutoScanEnabled] = useState(false)
  const [trafficEnabled, setTrafficEnabled] = useState(false)
  const [activeTab, setActiveTab] = useState('monitors')
  
  const [anomalies, setAnomalies] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  
  const [dnsBlocked, setDnsBlocked] = useState([])
  const [newDomain, setNewDomain] = useState('')
  const [dnsStatus, setDnsStatus] = useState(null)
  const [dnsRedirectIp, setDnsRedirectIp] = useState('0.0.0.0')
  const [dnsResolverHost, setDnsResolverHost] = useState('127.0.0.1')
  const [dnsResolverPort, setDnsResolverPort] = useState('5353')
  const [dnsUpstreamServer, setDnsUpstreamServer] = useState('8.8.8.8')
  const [dnsCopyStatus, setDnsCopyStatus] = useState('')
  const [dnsPresetCopyStatus, setDnsPresetCopyStatus] = useState('')
  
  const [defenseRules, setDefenseRules] = useState(null)
  const [defenseStatus, setDefenseStatus] = useState(null)
  const [playbooks, setPlaybooks] = useState([])
  const [blockedIPs, setBlockedIPs] = useState([])
  const [quarantinedDevices, setQuarantinedDevices] = useState([])
  const [manualDefenseIP, setManualDefenseIP] = useState('')
  const [manualQuarantineProfile, setManualQuarantineProfile] = useState('restricted_network')
  const [securityEvents, setSecurityEvents] = useState([])
  
  const [vulnReport, setVulnReport] = useState(null)

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const handleSecurityEvent = (event) => {
      const payload = event.detail
      if (!payload) {
        return
      }
      setSecurityEvents((current) => {
        const next = [payload, ...current.filter((item) => item.id !== payload.id)]
        return next.slice(0, 12)
      })
    }

    window.addEventListener('sentinel:security-event', handleSecurityEvent)
    return () => window.removeEventListener('sentinel:security-event', handleSecurityEvent)
  }, [])

  useEffect(() => {
    const handleTrafficStats = (event) => {
      if (event.detail) {
        setTrafficStats(event.detail)
      }
    }

    const handleDefenseStatus = (event) => {
      if (event.detail) {
        setDefenseStatus(event.detail)
      }
    }

    const handleDnsStats = (event) => {
      if (event.detail) {
        setDnsStatus(event.detail)
      }
    }

    window.addEventListener('sentinel:traffic-stats', handleTrafficStats)
    window.addEventListener('sentinel:defense-status', handleDefenseStatus)
    window.addEventListener('sentinel:dns-stats', handleDnsStats)
    return () => {
      window.removeEventListener('sentinel:traffic-stats', handleTrafficStats)
      window.removeEventListener('sentinel:defense-status', handleDefenseStatus)
      window.removeEventListener('sentinel:dns-stats', handleDnsStats)
    }
  }, [])

  const fetchData = async () => {
    try {
      const [statusRes, trafficRes, logsRes, dnsRes, dnsStatsRes, defenseRes, defenseStatusRes, playbooksRes, blockedRes, quarantinedRes, eventsRes] = await Promise.all([
        api.get(`${API_URL}/api/v1/status`),
        api.get(`${API_URL}/api/v1/traffic/stats`).catch(() => ({ data: {} })),
        api.get(`${API_URL}/api/v1/logs?lines=30`),
        api.get(`${API_URL}/api/v1/dns/blocked`).catch(() => ({ data: { domains: [] } })),
        api.get(`${API_URL}/api/v1/dns/stats`).catch(() => ({ data: {} })),
        api.get(`${API_URL}/api/v1/defense/rules`).catch(() => ({ data: {} })),
        api.get(`${API_URL}/api/v1/defense/status`).catch(() => ({ data: {} })),
        api.get(`${API_URL}/api/v1/defense/playbooks`).catch(() => ({ data: { playbooks: [] } })),
        api.get(`${API_URL}/api/v1/defense/blocked`).catch(() => ({ data: { blocked_ips: [] } })),
        api.get(`${API_URL}/api/v1/defense/quarantined`).catch(() => ({ data: { devices: [] } })),
        api.get(`${API_URL}/api/v1/events/security?limit=12`).catch(() => ({ data: { events: [] } }))
      ])
      
      setTrafficStats(trafficRes.data)
      setLogs(logsRes.data.logs || [])
      setAutoScanEnabled(statusRes.data.auto_scan_enabled || false)
      setTrafficEnabled(statusRes.data.traffic_monitor_enabled || false)
      setDnsBlocked(dnsRes.data.domains || [])
      setDnsStatus(dnsStatsRes.data || {})
      setDnsRedirectIp(dnsStatsRes.data?.redirect_ip || '0.0.0.0')
      setDnsResolverHost(String(dnsStatsRes.data?.resolver_host || '127.0.0.1'))
      setDnsResolverPort(String(dnsStatsRes.data?.resolver_port || '5353'))
      setDnsUpstreamServer(String(dnsStatsRes.data?.upstream_server || '8.8.8.8'))
      setDefenseRules(defenseRes.data || {})
      setDefenseStatus(defenseStatusRes.data || {})
      setPlaybooks(playbooksRes.data.playbooks || [])
      setBlockedIPs(blockedRes.data.blocked_ips || [])
      setQuarantinedDevices(quarantinedRes.data.devices || [])
      setSecurityEvents(eventsRes.data.events || [])
    } catch (err) {
      console.error('Failed to fetch monitor data:', err)
    } finally {
      setLoading(false)
    }
  }

  const startAutoScan = async () => {
    try {
      await api.post(`${API_URL}/api/v1/auto-scan/start`)
      setAutoScanEnabled(true)
    } catch (err) {
      console.error('Failed to start auto scan:', err)
    }
  }

  const stopAutoScan = async () => {
    try {
      await api.post(`${API_URL}/api/v1/auto-scan/stop`)
      setAutoScanEnabled(false)
    } catch (err) {
      console.error('Failed to stop auto scan:', err)
    }
  }

  const startTraffic = async () => {
    try {
      await api.post(`${API_URL}/api/v1/traffic/start`)
      setTrafficEnabled(true)
    } catch (err) {
      console.error('Failed to start traffic monitor:', err)
    }
  }

  const stopTraffic = async () => {
    try {
      await api.post(`${API_URL}/api/v1/traffic/stop`)
      setTrafficEnabled(false)
    } catch (err) {
      console.error('Failed to stop traffic monitor:', err)
    }
  }

  const runAnomalyDetection = async () => {
    setAnalyzing(true)
    try {
      const res = await api.get(`${API_URL}/api/v1/analyze/network`)
      setAnomalies(res.data)
    } catch (err) {
      console.error('Anomaly detection failed:', err)
    } finally {
      setAnalyzing(false)
    }
  }

  const trainModel = async () => {
    try {
      const res = await api.post(`${API_URL}/api/v1/analyze/train`)
      alert(res.data.message || `Training ${res.data.status}`)
    } catch (err) {
      console.error('Training failed:', err)
    }
  }

  const blockDomain = async () => {
    if (!newDomain.trim()) return
    try {
      await api.post(`${API_URL}/api/v1/dns/block`, null, { params: { domain: newDomain } })
      setNewDomain('')
      fetchData()
    } catch (err) {
      console.error('Failed to block domain:', err)
    }
  }

  const unblockDomain = async (domain) => {
    try {
      await api.post(`${API_URL}/api/v1/dns/unblock`, null, { params: { domain } })
      fetchData()
    } catch (err) {
      console.error('Failed to unblock domain:', err)
    }
  }

  const configureDnsSinkhole = async (enabled) => {
    try {
      const res = await api.post(`${API_URL}/api/v1/dns/configure`, null, {
        params: { enabled, redirect_ip: dnsRedirectIp || '0.0.0.0' },
      })
      setDnsStatus(res.data)
      fetchData()
    } catch (err) {
      console.error('Failed to configure DNS sinkhole:', err)
    }
  }

  const configureDnsResolver = async (resolverEnabled) => {
    try {
      const res = await api.post(`${API_URL}/api/v1/dns/configure`, null, {
        params: {
          resolver_enabled: resolverEnabled,
          resolver_host: dnsResolverHost || '127.0.0.1',
          resolver_port: Number.parseInt(dnsResolverPort, 10) || 5353,
          upstream_server: dnsUpstreamServer || '8.8.8.8',
        },
      })
      setDnsStatus(res.data)
      fetchData()
    } catch (err) {
      console.error('Failed to configure DNS resolver:', err)
    }
  }

  const syncDnsSinkhole = async () => {
    try {
      const res = await api.post(`${API_URL}/api/v1/dns/sync`)
      setDnsStatus((current) => ({ ...(current || {}), ...res.data }))
      fetchData()
    } catch (err) {
      console.error('Failed to sync DNS sinkhole:', err)
    }
  }

  const copyDnsSetup = async () => {
    const setupBlock = [
      `Resolver host: ${dnsStatus?.resolver_host || dnsResolverHost || '127.0.0.1'}`,
      `Resolver port: ${dnsStatus?.resolver_port || dnsResolverPort || '5353'}`,
      `Upstream DNS: ${dnsStatus?.upstream_server || dnsUpstreamServer || '8.8.8.8'}`,
      `Sinkhole IP: ${dnsStatus?.redirect_ip || dnsRedirectIp || '0.0.0.0'}`,
      '',
      ...((dnsStatus?.setup_steps || []).map((step, index) => `${index + 1}. ${step}`)),
    ].join('\n')

    try {
      await navigator.clipboard.writeText(setupBlock)
      setDnsCopyStatus('Copied setup block')
    } catch (err) {
      console.error('Failed to copy DNS setup block:', err)
      setDnsCopyStatus('Copy failed')
    } finally {
      window.setTimeout(() => setDnsCopyStatus(''), 2000)
    }
  }

  const copyDnsPreset = async (preset) => {
    const content = [
      preset.title,
      preset.target,
      preset.summary,
      '',
      preset.copy_block || '',
      '',
      ...((preset.steps || []).map((step, index) => `${index + 1}. ${step}`)),
    ].join('\n')
    try {
      await navigator.clipboard.writeText(content)
      setDnsPresetCopyStatus(`Copied ${preset.title}`)
    } catch (err) {
      console.error('Failed to copy DNS preset:', err)
      setDnsPresetCopyStatus(`Copy failed for ${preset.title}`)
    } finally {
      window.setTimeout(() => setDnsPresetCopyStatus(''), 2000)
    }
  }

  const blockIP = async (ip) => {
    if (!ip?.trim()) return
    try {
      await api.post(`${API_URL}/api/v1/defense/block/${ip}`)
      setManualDefenseIP('')
      fetchData()
    } catch (err) {
      console.error('Failed to block IP:', err)
    }
  }

  const unblockIP = async (ip) => {
    try {
      await api.post(`${API_URL}/api/v1/defense/unblock/${ip}`)
      fetchData()
    } catch (err) {
      console.error('Failed to unblock IP:', err)
    }
  }

  const quarantineIP = async (ip) => {
    if (!ip?.trim()) return
    try {
      const scope = manualQuarantineProfile === 'full_isolation'
        ? 'all_traffic'
        : manualQuarantineProfile === 'segment_isolation'
          ? 'network_segment'
        : manualQuarantineProfile === 'critical_service_isolation'
          ? 'critical_services'
          : 'lan_traffic'
      await api.post(`${API_URL}/api/v1/defense/quarantine/${ip}`, null, {
        params: { profile: manualQuarantineProfile, scope },
      })
      setManualDefenseIP('')
      fetchData()
    } catch (err) {
      console.error('Failed to quarantine IP:', err)
    }
  }

  const unquarantineIP = async (ip) => {
    try {
      await api.post(`${API_URL}/api/v1/defense/unquarantine/${ip}`)
      fetchData()
    } catch (err) {
      console.error('Failed to unquarantine IP:', err)
    }
  }

  const updateDefenseRule = async (rule, value) => {
    try {
      await api.post(`${API_URL}/api/v1/defense/rules`, null, { params: { rule, value } })
      fetchData()
    } catch (err) {
      console.error('Failed to update rule:', err)
    }
  }

  const executePlaybook = async (playbookName, ip) => {
    if (!ip?.trim()) return
    try {
      await api.post(`${API_URL}/api/v1/defense/playbooks/${playbookName}/execute`, {
        ip_address: ip,
      })
      setManualDefenseIP('')
      fetchData()
    } catch (err) {
      console.error('Failed to execute playbook:', err)
    }
  }

  const generateVulnReport = async () => {
    try {
      const res = await api.get(`${API_URL}/api/v1/reports/vulnerability`)
      setVulnReport(res.data)
    } catch (err) {
      console.error('Failed to generate report:', err)
    }
  }

  const tabs = [
    { id: 'monitors', label: 'Monitors', icon: Activity },
    { id: 'anomaly', label: 'AI Detection', icon: Brain },
    { id: 'defense', label: 'Auto-Defense', icon: Shield },
    { id: 'dns', label: 'DNS Filter', icon: Globe },
    { id: 'vuln', label: 'Vulnerabilities', icon: Bug },
  ]

  const booleanDefenseRules = Object.entries(defenseRules || {}).filter(([, value]) => typeof value === 'boolean')
  const informationalDefenseRules = Object.entries(defenseRules || {}).filter(([, value]) => typeof value !== 'boolean')
  const availableQuarantineProfiles = defenseStatus?.quarantine_profiles?.length
    ? defenseStatus.quarantine_profiles
    : ['restricted_network', 'full_isolation']

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white">System Monitor</h3>
          <p className="text-sm text-slate-400">Real-time monitoring and security controls</p>
        </div>
        <div className="flex gap-2 p-1 bg-slate-800 rounded-lg">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-all ${
                activeTab === tab.id 
                  ? 'bg-sentinel-600 text-white' 
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'monitors' && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="glass-panel rounded-xl p-6">
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Network className="w-5 h-5 text-sentinel-400" />
                Auto Network Scanner
              </h4>
              <p className="text-sm text-slate-400 mb-4">
                Automatically scans your network at regular intervals to detect new devices
              </p>
              <div className="flex gap-3">
                {!autoScanEnabled ? (
                  <button onClick={startAutoScan} className="sentinel-btn sentinel-btn-primary flex items-center gap-2">
                    <Play className="w-4 h-4" /> Start
                  </button>
                ) : (
                  <button onClick={stopAutoScan} className="sentinel-btn bg-red-600/20 text-red-400 border border-red-600/30 flex items-center gap-2">
                    <Square className="w-4 h-4" /> Stop
                  </button>
                )}
                <button onClick={fetchData} className="sentinel-btn bg-slate-700 text-white flex items-center gap-2">
                  <RefreshCw className="w-4 h-4" /> Refresh
                </button>
              </div>
              <div className="mt-3 text-sm text-slate-400">
                Status: {autoScanEnabled ? <span className="text-green-400">Running</span> : <span className="text-slate-500">Stopped</span>}
              </div>
            </div>

            <div className="glass-panel rounded-xl p-6">
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Activity className="w-5 h-5 text-sentinel-400" />
                Traffic Monitor
              </h4>
              <p className="text-sm text-slate-400 mb-4">Monitor real packet traffic through the local capture backend</p>
              <div className="flex gap-3">
                {!trafficEnabled ? (
                  <button onClick={startTraffic} className="sentinel-btn sentinel-btn-primary flex items-center gap-2">
                    <Play className="w-4 h-4" /> Start
                  </button>
                ) : (
                  <button onClick={stopTraffic} className="sentinel-btn bg-red-600/20 text-red-400 border border-red-600/30 flex items-center gap-2">
                    <Square className="w-4 h-4" /> Stop
                  </button>
                )}
              </div>
              <div className="mt-3 space-y-1 text-sm text-slate-400">
                <div>
                  Mode:{' '}
                  <span className={trafficStats?.mode === 'live_capture' ? 'text-green-400' : trafficStats?.mode === 'error' ? 'text-red-400' : 'text-slate-300'}>
                    {trafficStats?.mode || 'idle'}
                  </span>
                </div>
                <div>
                  Interface: <span className="text-slate-300">{trafficStats?.interface || 'auto'}</span>
                </div>
                {trafficStats?.last_error && (
                  <div className="text-red-400 text-xs">
                    Capture error: {trafficStats.last_error}
                  </div>
                )}
              </div>
              <div className="mt-4 grid grid-cols-2 gap-4">
                <div className="bg-slate-800 rounded-lg p-3">
                  <div className="text-2xl font-bold text-white">{trafficStats?.packets_captured || 0}</div>
                  <div className="text-xs text-slate-400">Packets Checked</div>
                </div>
                <div className="bg-slate-800 rounded-lg p-3">
                  <div className="text-2xl font-bold text-red-400">{trafficStats?.suspicious_count || 0}</div>
                  <div className="text-xs text-slate-400">Suspicious</div>
                </div>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-4">
                <div className="bg-slate-800 rounded-lg p-3">
                  <div className="text-2xl font-bold text-cyan-400">{trafficStats?.bytes_captured || 0}</div>
                  <div className="text-xs text-slate-400">Bytes Captured</div>
                </div>
                <div className="bg-slate-800 rounded-lg p-3">
                  <div className="text-2xl font-bold text-white">{trafficStats?.protocol_counts ? Object.keys(trafficStats.protocol_counts).length : 0}</div>
                  <div className="text-xs text-slate-400">Protocols Seen</div>
                </div>
              </div>
              {trafficStats?.suspicious_activity?.length > 0 && (
                <div className="mt-4">
                  <h5 className="text-sm font-medium text-white mb-2">Recent Suspicious Activity</h5>
                  <div className="space-y-1 max-h-32 overflow-auto">
                    {trafficStats.suspicious_activity.map((item, idx) => (
                      <div key={idx} className="text-xs bg-red-900/20 border border-red-800/30 rounded px-2 py-1 flex justify-between">
                        <span className="text-red-300 font-mono">{item.ip}:{item.port}</span>
                        <span className="text-red-400">{item.reason}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {trafficStats?.top_talkers?.length > 0 && (
                <div className="mt-4">
                  <h5 className="text-sm font-medium text-white mb-2">Top Talkers</h5>
                  <div className="space-y-1 max-h-32 overflow-auto">
                    {trafficStats.top_talkers.slice(0, 5).map((item, idx) => (
                      <div key={idx} className="text-xs bg-slate-800 border border-slate-700 rounded px-2 py-1 flex justify-between">
                        <span className="text-slate-200 font-mono">{item.key}</span>
                        <span className="text-cyan-400">{item.count} packets</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="glass-panel rounded-xl overflow-hidden">
            <div className="p-4 border-b border-[#1e293b]">
              <h4 className="text-lg font-semibold text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-sentinel-400" /> Activity Logs
              </h4>
            </div>
            <div className="max-h-64 overflow-auto">
              <div className="font-mono text-xs">
                {logs.map((log, idx) => (
                  <div key={idx} className={`px-4 py-1 border-b border-[#1e293b] ${
                    log.includes('ERROR') ? 'text-red-400' : log.includes('WARNING') ? 'text-yellow-400' : 'text-slate-300'
                  }`}>
                    {log}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}

      {activeTab === 'anomaly' && (
        <div className="space-y-6">
          <div className="glass-panel rounded-xl p-6">
            <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Brain className="w-5 h-5 text-purple-400" />
              AI-Powered Anomaly Detection
            </h4>
            <p className="text-sm text-slate-400 mb-4">
              Uses Machine Learning (Isolation Forest) to detect unusual network behavior and suspicious devices
            </p>
            <div className="flex gap-3 mb-6">
              <button 
                onClick={runAnomalyDetection} 
                disabled={analyzing}
                className="sentinel-btn sentinel-btn-primary flex items-center gap-2"
              >
                {analyzing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                {analyzing ? 'Analyzing...' : 'Run Analysis'}
              </button>
              <button onClick={trainModel} className="sentinel-btn bg-purple-600/20 text-purple-400 border border-purple-600/30 flex items-center gap-2">
                <Brain className="w-4 h-4" /> Train Model
              </button>
            </div>
            
            {anomalies && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-slate-800 rounded-lg p-4">
                  <div className="text-3xl font-bold text-white">{anomalies.total_devices}</div>
                  <div className="text-sm text-slate-400">Devices Analyzed</div>
                </div>
                <div className="bg-slate-800 rounded-lg p-4">
                  <div className="text-3xl font-bold text-red-400">{anomalies.anomalies_detected}</div>
                  <div className="text-sm text-slate-400">Anomalies Found</div>
                </div>
                <div className="bg-slate-800 rounded-lg p-4">
                  <div className="text-3xl font-bold text-green-400">{anomalies.total_devices - anomalies.anomalies_detected}</div>
                  <div className="text-sm text-slate-400">Normal Devices</div>
                </div>
              </div>
            )}
            
            {anomalies?.anomalies?.length > 0 && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
                <h5 className="text-red-400 font-medium mb-3">Detected Anomalies</h5>
                <div className="space-y-2">
                  {anomalies.anomalies.map((a, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-2">
                      <div>
                        <span className="text-white font-mono">{a.device_ip}</span>
                        <span className="text-slate-400 ml-2">Score: {(a.anomaly_score * 100).toFixed(1)}%</span>
                      </div>
                      <span className="text-xs text-slate-500">{a.method}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'defense' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="glass-panel rounded-xl p-6">
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Shield className="w-5 h-5 text-green-400" />
                Auto-Defense Rules
              </h4>
              <div className="mb-4 rounded-lg bg-slate-800 px-4 py-3 text-sm text-slate-300 space-y-1">
                <div>
                  Adapter: <span className="text-white">{defenseStatus?.adapter || defenseRules?.firewall_adapter || 'unknown'}</span>
                </div>
                <div>
                  Availability:{' '}
                  <span className={defenseStatus?.available ? 'text-green-400' : 'text-yellow-400'}>
                    {defenseStatus?.available ? 'available' : 'unavailable'}
                  </span>
                </div>
                <div>
                  Privileges:{' '}
                  <span className={defenseStatus?.admin ? 'text-green-400' : 'text-yellow-400'}>
                    {defenseStatus?.admin ? 'elevated' : 'not elevated'}
                  </span>
                </div>
                <div>
                  Quarantine profiles: <span className="text-white">{(defenseStatus?.quarantine_profiles || []).join(', ') || 'unknown'}</span>
                </div>
              </div>
              <div className="space-y-3">
                {booleanDefenseRules.map(([rule, value]) => (
                  <div key={rule} className="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-3">
                    <span className="text-slate-300 capitalize">{rule.replace(/_/g, ' ')}</span>
                    <button
                      onClick={() => updateDefenseRule(rule, !value)}
                      className={`w-12 h-6 rounded-full transition-colors ${value ? 'bg-green-500' : 'bg-slate-600'}`}
                    >
                      <div className={`w-4 h-4 rounded-full bg-white transition-transform ${value ? 'translate-x-7' : 'translate-x-1'}`} />
                    </button>
                  </div>
                ))}
                {informationalDefenseRules.map(([rule, value]) => (
                  <div key={rule} className="flex items-center justify-between bg-slate-900/70 rounded-lg px-4 py-3">
                    <span className="text-slate-400 capitalize">{rule.replace(/_/g, ' ')}</span>
                    <span className="text-slate-200 text-sm">{String(value)}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass-panel rounded-xl p-6">
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-yellow-400" />
                Manual Containment
              </h4>
              <div className="flex gap-3 mb-6">
                <input
                  type="text"
                  value={manualDefenseIP}
                  onChange={(e) => setManualDefenseIP(e.target.value)}
                  placeholder="Enter IP to block or quarantine"
                  className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white"
                />
                <select
                  value={manualQuarantineProfile}
                  onChange={(e) => setManualQuarantineProfile(e.target.value)}
                  className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white"
                >
                  {availableQuarantineProfiles.map((profile) => (
                    <option key={profile} value={profile}>
                      {QUARANTINE_PROFILE_LABELS[profile] || profile}
                    </option>
                  ))}
                </select>
                <button
                  onClick={() => blockIP(manualDefenseIP)}
                  className="sentinel-btn bg-red-600/20 text-red-300 border border-red-600/30"
                >
                  Block
                </button>
                <button
                  onClick={() => quarantineIP(manualDefenseIP)}
                  className="sentinel-btn bg-yellow-600/20 text-yellow-300 border border-yellow-600/30"
                >
                  Quarantine
                </button>
              </div>

              <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Lock className="w-5 h-5 text-red-400" />
                Blocked IPs
              </h4>
              {blockedIPs.length === 0 ? (
                <div className="text-center text-slate-400 py-8">No IPs blocked</div>
              ) : (
                <div className="space-y-2 max-h-64 overflow-auto">
                  {blockedIPs.map((ip, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-2">
                      <span className="text-white font-mono">{ip}</span>
                      <button
                        onClick={() => unblockIP(ip)}
                        className="text-green-400 hover:text-green-300 text-sm"
                      >
                        Unblock
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="glass-panel rounded-xl p-6">
            <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-yellow-400" />
              Quarantined Devices
            </h4>
            {quarantinedDevices.length === 0 ? (
              <div className="text-center text-slate-400 py-8">No devices are quarantined</div>
            ) : (
              <div className="space-y-2">
                {quarantinedDevices.map((device) => (
                  <div key={device.ip_address} className="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-3">
                    <div>
                      <div className="text-white font-mono">{device.ip_address}</div>
                      <div className="text-xs text-slate-500">
                        {device.hostname || 'unknown host'} | risk {device.risk_score ?? 0}
                      </div>
                      {device.containment?.active && (
                        <div className="text-xs text-yellow-300 mt-1 space-y-1">
                          <div>
                          {(QUARANTINE_PROFILE_LABELS[device.containment.profile] || device.containment.profile)} | {device.containment.scope}
                          {device.containment.ports?.length > 0 ? ` | ports ${device.containment.ports.join(', ')}` : ''}
                          {device.containment.segment_name ? ` | segment ${device.containment.segment_name}` : ''}
                          {device.containment.policy_name ? ` | policy ${device.containment.policy_name}` : ''}
                          {device.containment.condition_name ? ` | condition ${device.containment.condition_name}` : ''}
                          {device.containment.allowed_networks?.length > 0 ? ` | segments ${device.containment.allowed_networks.join(', ')}` : ''}
                          {device.containment.allowed_destinations?.length > 0 ? ` | allow ${device.containment.allowed_destinations.join(', ')}` : ''}
                        </div>
                          {formatDecisionTrace(device.containment.decision_trace).length > 0 && (
                            <div className="text-[11px] text-slate-400">
                              Decision trace: {formatDecisionTrace(device.containment.decision_trace).join(' -> ')}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => unquarantineIP(device.ip_address)}
                      className="text-green-400 hover:text-green-300 text-sm"
                    >
                      Release
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="glass-panel rounded-xl p-6">
            <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Zap className="w-5 h-5 text-cyan-400" />
              Response Playbooks
            </h4>
            {playbooks.length === 0 ? (
              <div className="text-center text-slate-400 py-8">No playbooks loaded</div>
            ) : (
              <div className="space-y-3">
                {playbooks.map((playbook) => (
                  <div key={playbook.name} className="rounded-lg border border-slate-700 bg-slate-800/70 px-4 py-3">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <div className="text-white font-medium">{playbook.title}</div>
                        <div className="text-xs text-slate-500">{playbook.trigger}</div>
                      </div>
                      <button
                        onClick={() => executePlaybook(playbook.name, manualDefenseIP)}
                        className="sentinel-btn bg-cyan-600/20 text-cyan-300 border border-cyan-600/30"
                      >
                        Run
                      </button>
                    </div>
                    <div className="mt-2 text-sm text-slate-300">{playbook.description}</div>
                    <div className="mt-2 text-xs text-slate-500">Steps: {playbook.steps.join(' -> ')}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="glass-panel rounded-xl p-6">
            <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <FileText className="w-5 h-5 text-cyan-400" />
              Security Event Timeline
            </h4>
            {securityEvents.length === 0 ? (
              <div className="text-center text-slate-400 py-8">No defense or monitoring events recorded yet</div>
            ) : (
              <div className="space-y-3">
                {securityEvents.map((event) => (
                  <div key={event.id} className="rounded-lg border border-slate-700 bg-slate-800/70 px-4 py-3">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <div className="text-white font-medium">{event.title}</div>
                        <div className="text-xs text-slate-500">
                          {event.source} | {event.event_type}
                          {event.target_ip ? ` | ${event.target_ip}` : ''}
                        </div>
                      </div>
                      <span className={`text-xs uppercase ${
                        event.severity === 'high'
                          ? 'text-red-400'
                          : event.severity === 'warning'
                            ? 'text-yellow-400'
                            : 'text-cyan-400'
                      }`}>
                        {event.severity}
                      </span>
                    </div>
                    {event.message && (
                      <div className="mt-2 text-sm text-slate-300">{event.message}</div>
                    )}
                    <div className="mt-2 text-xs text-slate-500">{event.created_at}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'dns' && (
        <div className="space-y-6">
          <div className="glass-panel rounded-xl p-6">
            <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Globe className="w-5 h-5 text-cyan-400" />
              DNS Filter
            </h4>
            <p className="text-sm text-slate-400 mb-4">Block malicious domains and sync local sinkhole entries into the hosts file</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              <div className="rounded-lg border border-slate-700 bg-slate-800/60 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">Sinkhole mode</span>
                  <span className={(dnsStatus?.enabled ? 'text-green-400' : 'text-yellow-400')}>
                    {dnsStatus?.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">Hosts file access</span>
                  <span className={(dnsStatus?.is_admin ? 'text-green-400' : 'text-yellow-400')}>
                    {dnsStatus?.is_admin ? 'Writable now' : 'Needs admin'}
                  </span>
                </div>
                <div className="text-xs text-slate-500 break-all">
                  {dnsStatus?.hosts_path || 'Hosts path unavailable'}
                </div>
                {dnsStatus?.last_sync_at && (
                  <div className="text-xs text-slate-500">
                    Last sync: {new Date(dnsStatus.last_sync_at).toLocaleString()}
                  </div>
                )}
                {dnsStatus?.last_error && (
                  <div className="text-xs text-red-400">{dnsStatus.last_error}</div>
                )}
                {dnsStatus?.last_resolver_error && (
                  <div className="text-xs text-red-400">{dnsStatus.last_resolver_error}</div>
                )}
              </div>

              <div className="rounded-lg border border-slate-700 bg-slate-800/60 p-4 space-y-3">
                <label className="block text-sm text-slate-400">Sinkhole redirect IP</label>
                <input
                  type="text"
                  value={dnsRedirectIp}
                  onChange={(e) => setDnsRedirectIp(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
                />
                <div className="flex gap-3">
                  <button onClick={() => configureDnsSinkhole(!(dnsStatus?.enabled))} className="sentinel-btn bg-slate-700 hover:bg-slate-600 text-white">
                    {dnsStatus?.enabled ? 'Disable sinkhole' : 'Enable sinkhole'}
                  </button>
                  <button onClick={syncDnsSinkhole} className="sentinel-btn sentinel-btn-primary">
                    Sync hosts file
                  </button>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              <div className="rounded-lg border border-slate-700 bg-slate-800/60 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">Resolver mode</span>
                  <span className={dnsStatus?.resolver_running ? 'text-green-400' : dnsStatus?.resolver_enabled ? 'text-yellow-400' : 'text-slate-400'}>
                    {dnsStatus?.resolver_running ? 'Running' : dnsStatus?.resolver_enabled ? 'Configured' : 'Disabled'}
                  </span>
                </div>
                <div className="text-xs text-slate-500">
                  Queries: {dnsStatus?.query_count || 0} | blocked: {dnsStatus?.blocked_query_count || 0} | forwarded: {dnsStatus?.forwarded_query_count || 0}
                </div>
                {dnsStatus?.port_conflicts && Object.keys(dnsStatus.port_conflicts).length > 0 && (
                  <div className="text-xs text-yellow-400">
                    Port conflict detected on {Object.keys(dnsStatus.port_conflicts).join(', ')}
                  </div>
                )}
                {dnsStatus?.resolver_started_at && (
                  <div className="text-xs text-slate-500">
                    Started: {new Date(dnsStatus.resolver_started_at).toLocaleString()}
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-slate-700 bg-slate-800/60 p-4 space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <input
                    type="text"
                    value={dnsResolverHost}
                    onChange={(e) => setDnsResolverHost(e.target.value)}
                    placeholder="Resolver host"
                    className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
                  />
                  <input
                    type="number"
                    value={dnsResolverPort}
                    onChange={(e) => setDnsResolverPort(e.target.value)}
                    placeholder="Port"
                    className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
                  />
                  <input
                    type="text"
                    value={dnsUpstreamServer}
                    onChange={(e) => setDnsUpstreamServer(e.target.value)}
                    placeholder="Upstream DNS"
                    className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
                  />
                </div>
                <div className="flex gap-3">
                  <button onClick={() => configureDnsResolver(!(dnsStatus?.resolver_enabled))} className="sentinel-btn bg-slate-700 hover:bg-slate-600 text-white">
                    {dnsStatus?.resolver_enabled ? 'Disable resolver' : 'Enable resolver'}
                  </button>
                </div>
              </div>
            </div>
            
            <div className="flex gap-3 mb-6">
              <input
                type="text"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                placeholder="Enter domain to block (e.g., malware.com)"
                className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white"
                onKeyDown={(e) => e.key === 'Enter' && blockDomain()}
              />
              <button onClick={blockDomain} className="sentinel-btn sentinel-btn-primary flex items-center gap-2">
                <Lock className="w-4 h-4" /> Block
              </button>
            </div>

            <div className="space-y-2">
              <h5 className="text-white font-medium">Blocked Domains ({dnsBlocked.length})</h5>
              {dnsBlocked.length === 0 ? (
                <div className="text-center text-slate-400 py-4">No domains blocked</div>
              ) : (
                <div className="max-h-64 overflow-auto">
                  {dnsBlocked.map((domain, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-2">
                      <span className="text-slate-300">{domain}</span>
                      <button onClick={() => unblockDomain(domain)} className="text-red-400 hover:text-red-300">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="mt-6">
              <h5 className="text-white font-medium mb-2">Hosts Preview</h5>
              <pre className="max-h-56 overflow-auto rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-xs text-slate-300 whitespace-pre-wrap">
                {dnsStatus?.preview || '# No preview available yet'}
              </pre>
            </div>

            <div className="mt-6 rounded-lg border border-slate-700 bg-slate-800/60 p-4">
              <div className="flex items-center justify-between gap-3 mb-2">
                <h5 className="text-white font-medium">Setup Guidance</h5>
                <div className="flex items-center gap-3">
                  {dnsCopyStatus && <span className="text-xs text-cyan-300">{dnsCopyStatus}</span>}
                  <button onClick={copyDnsSetup} className="sentinel-btn bg-slate-700 hover:bg-slate-600 text-white">
                    Copy setup
                  </button>
                </div>
              </div>
              <pre className="mb-3 rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-xs text-slate-300 whitespace-pre-wrap">
{`Resolver host: ${dnsStatus?.resolver_host || dnsResolverHost || '127.0.0.1'}
Resolver port: ${dnsStatus?.resolver_port || dnsResolverPort || '5353'}
Upstream DNS: ${dnsStatus?.upstream_server || dnsUpstreamServer || '8.8.8.8'}
Sinkhole IP: ${dnsStatus?.redirect_ip || dnsRedirectIp || '0.0.0.0'}`}
              </pre>
              <div className="space-y-2 text-sm text-slate-300">
                {(dnsStatus?.setup_steps || []).map((step, index) => (
                  <div key={`${step}-${index}`}>{index + 1}. {step}</div>
                ))}
              </div>
            </div>

            <div className="mt-6 rounded-lg border border-slate-700 bg-slate-800/60 p-4">
              <div className="flex items-center justify-between gap-3 mb-3">
                <h5 className="text-white font-medium">Deployment Presets</h5>
                {dnsPresetCopyStatus && <span className="text-xs text-cyan-300">{dnsPresetCopyStatus}</span>}
              </div>
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                {(dnsStatus?.deployment_presets || []).map((preset) => (
                  <div key={preset.id} className="rounded-lg border border-slate-700 bg-slate-900/70 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-white font-medium">{preset.title}</div>
                        <div className="text-xs text-slate-500">{preset.target}</div>
                      </div>
                      <button onClick={() => copyDnsPreset(preset)} className="sentinel-btn bg-slate-700 hover:bg-slate-600 text-white">
                        Copy preset
                      </button>
                    </div>
                    <div className="mt-2 text-sm text-slate-300">{preset.summary}</div>
                    <pre className="mt-3 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-300 whitespace-pre-wrap">
                      {preset.copy_block}
                    </pre>
                    <div className="mt-3 space-y-1 text-xs text-slate-400">
                      {(preset.steps || []).map((step, index) => (
                        <div key={`${preset.id}-${index}`}>{index + 1}. {step}</div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'vuln' && (
        <div className="space-y-6">
          <div className="glass-panel rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-semibold text-white flex items-center gap-2">
                <Bug className="w-5 h-5 text-orange-400" />
                Vulnerability Report
              </h4>
              <button onClick={generateVulnReport} className="sentinel-btn sentinel-btn-primary flex items-center gap-2">
                <RefreshCw className="w-4 h-4" /> Generate Report
              </button>
            </div>
            
            {!vulnReport ? (
              <div className="text-center text-slate-400 py-8">Click "Generate Report" to scan for vulnerabilities</div>
            ) : (
              <div className="space-y-6">
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <div className="bg-slate-800 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-white">{vulnReport.summary?.total_devices}</div>
                    <div className="text-xs text-slate-400">Devices</div>
                  </div>
                  <div className="bg-red-500/20 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-red-400">{vulnReport.summary?.critical}</div>
                    <div className="text-xs text-slate-400">Critical</div>
                  </div>
                  <div className="bg-orange-500/20 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-orange-400">{vulnReport.summary?.high}</div>
                    <div className="text-xs text-slate-400">High</div>
                  </div>
                  <div className="bg-yellow-500/20 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-yellow-400">{vulnReport.summary?.medium}</div>
                    <div className="text-xs text-slate-400">Medium</div>
                  </div>
                  <div className="bg-slate-700 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-slate-300">{vulnReport.summary?.low}</div>
                    <div className="text-xs text-slate-400">Low</div>
                  </div>
                </div>
                
                <div className="bg-slate-800 rounded-lg p-4">
                  <h5 className="text-white font-medium mb-2">Network Risk Score</h5>
                  <div className="flex items-center gap-4">
                    <div className="text-3xl font-bold text-white">{vulnReport.risk_score}</div>
                    <div className="flex-1 h-3 bg-slate-700 rounded-full overflow-hidden">
                      <div 
                        className={`h-full ${vulnReport.risk_score > 70 ? 'bg-red-500' : vulnReport.risk_score > 40 ? 'bg-orange-500' : 'bg-green-500'}`}
                        style={{ width: `${vulnReport.risk_score}%` }}
                      />
                    </div>
                  </div>
                </div>

                <div className="bg-slate-800 rounded-lg p-4">
                  <h5 className="text-white font-medium mb-2">Recommendations</h5>
                  <ul className="space-y-2">
                    {vulnReport.recommendations?.map((rec, idx) => (
                      <li key={idx} className="text-slate-300 flex items-center gap-2">
                        <Zap className="w-4 h-4 text-yellow-400" /> {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
