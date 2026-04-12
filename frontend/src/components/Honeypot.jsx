import { useState, useEffect } from 'react'
import { Play, Square, Server, Terminal, Shield, AlertTriangle, RefreshCw, Info, ExternalLink, FileText, X } from 'lucide-react'
import api, { API_URL } from '../lib/api'

const HONEYPOT_SERVICES = [
  { listenPort: 2222, mimicPort: 22, name: 'SSH', description: 'Fake SSH server - traps SSH brute force', risk: 'high' },
  { listenPort: 2323, mimicPort: 23, name: 'Telnet', description: 'Fake Telnet - traps legacy attacks', risk: 'critical' },
  { listenPort: 8081, mimicPort: 80, name: 'HTTP', description: 'Fake web server - traps web scanners', risk: 'medium' },
  { listenPort: 8443, mimicPort: 443, name: 'HTTPS', description: 'Fake secure web server', risk: 'medium' },
  { listenPort: 2443, mimicPort: 445, name: 'SMB', description: 'Fake Windows file sharing - traps SMB attacks', risk: 'critical' },
  { listenPort: 3389, mimicPort: 3389, name: 'RDP', description: 'Fake Remote Desktop - traps RDP attacks', risk: 'high' },
  { listenPort: 2121, mimicPort: 21, name: 'FTP', description: 'Fake FTP server - traps FTP attacks', risk: 'high' },
  { listenPort: 2525, mimicPort: 25, name: 'SMTP', description: 'Fake mail server - traps email scanner', risk: 'medium' },
]

const getServiceName = (port) => {
  const service = HONEYPOT_SERVICES.find(s => s.listenPort === port)
  return service ? service.name : 'custom'
}

export default function HoneypotPanel() {
  const [runningServices, setRunningServices] = useState([])
  const [capturedAttacks, setCapturedAttacks] = useState([])
  const [loading, setLoading] = useState(true)
  const [honeypotActive, setHoneypotActive] = useState(false)
  const [selectedAttack, setSelectedAttack] = useState(null)
  const [attackDetails, setAttackDetails] = useState(null)
  const [analysisReport, setAnalysisReport] = useState(null)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      const [servicesRes, attacksRes] = await Promise.all([
        api.get(`${API_URL}/api/v1/honeypot/services`).catch(() => ({ data: { running: [] } })),
        api.get(`${API_URL}/api/v1/honeypot/attacks`).catch(() => ({ data: { attacks: [] } }))
      ])
      
      setRunningServices(servicesRes.data.running || [])
      setCapturedAttacks(attacksRes.data.attacks || [])
      setHoneypotActive(servicesRes.data.stats?.active || false)
    } catch (err) {
      console.error('Failed to fetch honeypot data:', err)
    } finally {
      setLoading(false)
    }
  }

  const startService = async (port) => {
    try {
      const service = getServiceName(port)
      await api.post(`${API_URL}/api/v1/honeypot/start`, null, { params: { port, service } })
      fetchData()
    } catch (err) {
      console.error('Failed to start honeypot service:', err)
    }
  }

  const stopService = async (port) => {
    try {
      await api.post(`${API_URL}/api/v1/honeypot/stop`, null, { params: { port } })
      fetchData()
    } catch (err) {
      console.error('Failed to stop honeypot service:', err)
    }
  }

  const viewAttackDetails = async (attackId) => {
    try {
      const [fullRes, reportRes] = await Promise.all([
        api.get(`${API_URL}/api/v1/honeypot/attack/${attackId}/full`).catch(() => ({ data: {} })),
        api.get(`${API_URL}/api/v1/honeypot/attack/${attackId}/report`).catch(() => ({ data: {} }))
      ])
      
      setSelectedAttack(attackId)
      setAttackDetails(fullRes.data.attack || null)
      setAnalysisReport(reportRes.data.report || null)
    } catch (err) {
      console.error('Failed to fetch attack details:', err)
    }
  }

  const closeAttackModal = () => {
    setSelectedAttack(null)
    setAttackDetails(null)
    setAnalysisReport(null)
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-white">Honeypot Manager</h3>
        <p className="text-sm text-slate-400">Deploy decoy services to trap and analyze attackers</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-panel rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-semibold text-white flex items-center gap-2">
                <Server className="w-5 h-5 text-purple-400" />
                Deploy Honeypot Services
              </h4>
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${honeypotActive ? 'bg-green-500 animate-pulse' : 'bg-slate-500'}`} />
                <span className="text-sm text-slate-400">{honeypotActive ? 'Active' : 'Inactive'}</span>
              </div>
            </div>
            
            <p className="text-sm text-slate-400 mb-6">
              Deploy fake services on your network to lure attackers. All connections are logged for analysis.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {HONEYPOT_SERVICES.map((service) => (
                <div key={service.listenPort} className="bg-slate-800/50 rounded-xl p-4 border border-slate-700">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-white font-mono font-bold">{service.listenPort}</span>
                      <span className="text-slate-300">→ {service.name} (:{service.mimicPort})</span>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded ${
                      service.risk === 'critical' ? 'bg-red-500/20 text-red-400' :
                      service.risk === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {service.risk}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mb-3">{service.description}</p>
                  <button
                    onClick={() => runningServices.includes(service.listenPort) ? stopService(service.listenPort) : startService(service.listenPort)}
                    className={`w-full py-2 rounded-lg text-sm flex items-center justify-center gap-2 transition-colors ${
                      runningServices.includes(service.listenPort)
                        ? 'bg-red-600/20 text-red-400 border border-red-600/30 hover:bg-red-600/30'
                        : 'bg-green-600/20 text-green-400 border border-green-600/30 hover:bg-green-600/30'
                    }`}
                  >
                    {runningServices.includes(service.listenPort) ? (
                      <>
                        <Square className="w-4 h-4" /> Stop
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" /> Deploy
                      </>
                    )}
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-panel rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-semibold text-white flex items-center gap-2">
                <Terminal className="w-5 h-5 text-green-400" />
                Captured Attacks
              </h4>
              <button onClick={fetchData} className="text-slate-400 hover:text-white">
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>

            {capturedAttacks.length === 0 ? (
              <div className="text-center py-8 text-slate-400">
                <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No attacks captured yet</p>
                <p className="text-sm">Deploy honeypot services to start trapping attackers</p>
              </div>
            ) : (
              <div className="space-y-3 max-h-96 overflow-auto">
                {capturedAttacks.map((attack, idx) => (
                  <div key={idx} className="bg-slate-800 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-red-400" />
                        <span className="text-white font-mono">{attack.source_ip}</span>
                      </div>
                      <span className="text-xs text-slate-500">{attack.timestamp}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div>
                        <span className="text-slate-500">Listen Port: </span>
                        <span className="text-white">{attack.listen_port}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Mimics: </span>
                        <span className="text-white">{attack.service} (:{attack.mimic_port})</span>
                      </div>
                      {attack.commands && (
                        <div className="col-span-2">
                          <span className="text-slate-500">Commands: </span>
                          <span className="text-red-400 font-mono text-xs">
                            {typeof attack.commands === 'string' ? attack.commands.substring(0, 100) : attack.commands.join(', ')}
                          </span>
                        </div>
                      )}
                      <div className="col-span-2">
                        <button
                          onClick={() => viewAttackDetails(attack.attack_id)}
                          className="text-xs text-cyan-400 hover:text-cyan-300 mt-1"
                        >
                          View Full Details & Analysis →
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="space-y-4">
          <div className="glass-panel rounded-xl p-5">
            <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              About Honeypots
            </h4>
            <div className="space-y-3 text-sm text-slate-400">
              <p>Honeypots are decoy systems designed to:</p>
              <ul className="space-y-2 ml-2">
                <li className="flex items-start gap-2">
                  <ExternalLink className="w-4 h-4 mt-0.5 text-slate-500" />
                  <span>Detect attackers without risking real systems</span>
                </li>
                <li className="flex items-start gap-2">
                  <Terminal className="w-4 h-4 mt-0.5 text-slate-500" />
                  <span>Log attack techniques and payloads</span>
                </li>
                <li className="flex items-start gap-2">
                  <Shield className="w-4 h-4 mt-0.5 text-slate-500" />
                  <span>Divert attackers from real assets</span>
                </li>
              </ul>
            </div>
          </div>

          <div className="glass-panel rounded-xl p-5">
            <h4 className="font-semibold text-white mb-3">Quick Stats</h4>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-slate-400">Services Running</span>
                <span className="text-white font-medium">{runningServices.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Attacks Captured</span>
                <span className="text-white font-medium">{capturedAttacks.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Unique Attackers</span>
                <span className="text-white font-medium">{new Set(capturedAttacks.map(a => a.source_ip)).size}</span>
              </div>
            </div>
          </div>

          <div className="glass-panel rounded-xl p-5 bg-purple-500/10 border-purple-500/30">
            <h4 className="font-semibold text-white mb-2 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-purple-400" />
              Security Notice
            </h4>
            <p className="text-sm text-slate-400">
              Honeypots should only be used on isolated networks or with proper firewall rules to prevent being used to attack others.
            </p>
          </div>
        </div>
      </div>

      {selectedAttack && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-slate-800 rounded-xl max-w-2xl w-full max-h-[90vh] overflow-auto">
            <div className="flex items-center justify-between p-4 border-b border-slate-700">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-cyan-400" />
                Attack Details
              </h3>
              <button onClick={closeAttackModal} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="p-4 space-y-4">
              {attackDetails && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-slate-700/50 rounded-lg p-3">
                      <div className="text-xs text-slate-400">Attack ID</div>
                      <div className="text-white font-mono">{attackDetails.attack_id}</div>
                    </div>
                    <div className="bg-slate-700/50 rounded-lg p-3">
                      <div className="text-xs text-slate-400">Source IP</div>
                      <div className="text-white font-mono">{attackDetails.source_ip}</div>
                    </div>
                    <div className="bg-slate-700/50 rounded-lg p-3">
                      <div className="text-xs text-slate-400">Listen Port</div>
                      <div className="text-white">{attackDetails.listen_port}</div>
                    </div>
                    <div className="bg-slate-700/50 rounded-lg p-3">
                      <div className="text-xs text-slate-400">Mimics</div>
                      <div className="text-white">{attackDetails.service} (:{attackDetails.mimic_port})</div>
                    </div>
                    <div className="bg-slate-700/50 rounded-lg p-3 col-span-2">
                      <div className="text-xs text-slate-400">Timestamp</div>
                      <div className="text-white">{attackDetails.timestamp}</div>
                    </div>
                  </div>
                  
                  <div className="bg-slate-700/50 rounded-lg p-3">
                    <div className="text-xs text-slate-400 mb-2">Captured Commands</div>
                    <div className="font-mono text-sm text-red-400 whitespace-pre-wrap">
                      {Array.isArray(attackDetails.commands) 
                        ? attackDetails.commands.join('\n') 
                        : attackDetails.commands}
                    </div>
                  </div>
                  
                  {attackDetails.raw_data && (
                    <div className="bg-slate-700/50 rounded-lg p-3">
                      <div className="text-xs text-slate-400 mb-2">Raw Data (Hex)</div>
                      <div className="font-mono text-xs text-slate-500 break-all">
                        {attackDetails.raw_data}
                      </div>
                    </div>
                  )}
                </div>
              )}
              
              {analysisReport ? (
                <div className="bg-purple-900/30 border border-purple-500/30 rounded-lg p-4">
                  <div className="text-sm font-semibold text-purple-400 mb-2 flex items-center gap-2">
                    <FileText className="w-4 h-4" />
                    LLM Analysis Report
                  </div>
                  <div className="text-sm text-slate-300 whitespace-pre-wrap">
                    {analysisReport}
                  </div>
                </div>
              ) : (
                <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                  <div className="text-slate-400 text-sm">LLM analysis not available</div>
                  <div className="text-slate-500 text-xs mt-1">Make sure Ollama is running with phi2 model</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
