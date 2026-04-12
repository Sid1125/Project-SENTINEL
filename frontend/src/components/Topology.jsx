import { useState, useEffect } from 'react'
import { Network, Smartphone, Laptop, Server, Router, Tv, Wifi, RefreshCw, AlertTriangle } from 'lucide-react'
import api, { API_URL } from '../lib/api'

const getDeviceIcon = (vendor, hostname) => {
  const v = (vendor || '').toLowerCase()
  const h = (hostname || '').toLowerCase()
  
  if (v.includes('apple') || h.includes('iphone') || h.includes('ipad')) return Smartphone
  if (v.includes('dell') || v.includes('hp') || v.includes('lenovo') || v.includes('microsoft')) return Laptop
  if (v.includes('cisco') || v.includes('netgear') || v.includes('tp-link') || v.includes('router')) return Router
  if (v.includes('samsung') || v.includes('lg') || h.includes('tv')) return Tv
  if (v.includes('raspberry')) return Server
  if (v.includes('intel') || v.includes('realtek')) return Wifi
  return Laptop
}

const getDeviceColor = (device) => {
  if (device.is_blocked) return '#ef4444'
  if (device.is_trusted) return '#22c55e'
  if (device.risk_score >= 70) return '#ef4444'
  if (device.risk_score >= 40) return '#f59e0b'
  return '#0ea5e9'
}

export default function NetworkTopology() {
  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedDevice, setSelectedDevice] = useState(null)

  useEffect(() => {
    fetchDevices()
  }, [])

  const fetchDevices = async () => {
    try {
      const res = await api.get(`${API_URL}/api/v1/devices`)
      setDevices(res.data.devices || [])
    } catch (err) {
      console.error('Failed to fetch devices:', err)
    } finally {
      setLoading(false)
    }
  }

  const gateway = devices.find(d => d.ip_address?.endsWith('.1') || d.ip_address?.includes('192.168.1.1'))
  const otherDevices = devices.filter(d => d.ip_address !== gateway?.ip_address)

  const positions = {
    gateway: { x: 400, y: 50 },
    ...Object.fromEntries(otherDevices.map((d, i) => {
      const angle = (i / otherDevices.length) * 2 * Math.PI
      const radius = 180
      const x = 400 + Math.cos(angle) * radius
      const y = 200 + Math.sin(angle) * radius
      return [d.ip_address, { x, y }]
    }))
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white">Network Topology</h3>
          <p className="text-sm text-slate-400">Visual map of your network devices</p>
        </div>
        <button onClick={fetchDevices} className="sentinel-btn bg-slate-700 hover:bg-slate-600 text-white flex items-center gap-2">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 glass-panel rounded-xl p-6">
          <div className="relative h-[500px]">
            <svg width="100%" height="100%" viewBox="0 0 800 450">
              <defs>
                <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="#475569" />
                </marker>
              </defs>

              {gateway && otherDevices.map(d => (
                <line
                  key={`line-${d.ip_address}`}
                  x1={positions.gateway.x}
                  y1={positions.gateway.y + 20}
                  x2={positions[d.ip_address]?.x || 400}
                  y2={positions[d.ip_address]?.y - 20 || 200}
                  stroke="#475569"
                  strokeWidth="2"
                  strokeDasharray="5,5"
                  markerEnd="url(#arrowhead)"
                />
              ))}

              {gateway && (
                <g 
                  className="cursor-pointer"
                  onClick={() => setSelectedDevice(gateway)}
                >
                  <circle cx={positions.gateway.x} cy={positions.gateway.y} r="30" fill="#22c55e" opacity="0.3">
                    <animate attributeName="r" values="30;35;30" dur="2s" repeatCount="indefinite" />
                  </circle>
                  <circle cx={positions.gateway.x} cy={positions.gateway.y} r="25" fill="#22c55e" />
                  <text x={positions.gateway.x} y={positions.gateway.y} textAnchor="middle" dy="5" fill="white" fontSize="12" fontWeight="bold">GW</text>
                  <text x={positions.gateway.x} y={positions.gateway.y + 45} textAnchor="middle" fill="#94a3b8" fontSize="11">{gateway.ip_address}</text>
                </g>
              )}

              {otherDevices.map(d => {
                const Icon = getDeviceIcon(d.vendor, d.hostname)
                const pos = positions[d.ip_address] || { x: 400, y: 200 }
                const color = getDeviceColor(d)
                
                return (
                  <g 
                    key={d.ip_address} 
                    className="cursor-pointer"
                    onClick={() => setSelectedDevice(d)}
                  >
                    <circle cx={pos.x} cy={pos.y} r="25" fill={color} opacity="0.3">
                      <animate attributeName="r" values="25;30;25" dur="2s" repeatCount="indefinite" />
                    </circle>
                    <circle cx={pos.x} cy={pos.y} r="20" fill={color} />
                    <text x={pos.x} y={pos.y} textAnchor="middle" dy="4" fill="white" fontSize="10">
                      <Icon size={16} />
                    </text>
                    <text x={pos.x} y={pos.y + 35} textAnchor="middle" fill="#94a3b8" fontSize="10">{d.ip_address}</text>
                    {d.hostname && (
                      <text x={pos.x} y={pos.y + 48} textAnchor="middle" fill="#64748b" fontSize="9" maxWidth="80">
                        {d.hostname.substring(0, 12)}
                      </text>
                    )}
                  </g>
                )
              })}
            </svg>

            <div className="absolute bottom-4 right-4 flex gap-4 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-green-500" />
                <span className="text-slate-400">Trusted</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-500" />
                <span className="text-slate-400">Normal</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-yellow-500" />
                <span className="text-slate-400">Warning</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span className="text-slate-400">Critical/Blocked</span>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="glass-panel rounded-xl p-4">
            <h4 className="font-semibold text-white mb-3">Network Stats</h4>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-slate-400">Total Devices</span>
                <span className="text-white font-medium">{devices.length}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-400">Trusted</span>
                <span className="text-green-400 font-medium">{devices.filter(d => d.is_trusted).length}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-400">Blocked</span>
                <span className="text-red-400 font-medium">{devices.filter(d => d.is_blocked).length}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-400">High Risk</span>
                <span className="text-red-400 font-medium">{devices.filter(d => d.risk_score >= 70).length}</span>
              </div>
            </div>
          </div>

          <div className="glass-panel rounded-xl p-4">
            <h4 className="font-semibold text-white mb-3">Device List</h4>
            <div className="space-y-2 max-h-80 overflow-auto">
              {devices.map((d, idx) => {
                const Icon = getDeviceIcon(d.vendor, d.hostname)
                const color = getDeviceColor(d)
                return (
                  <button
                    key={idx}
                    onClick={() => setSelectedDevice(d)}
                    className={`w-full flex items-center gap-3 p-2 rounded-lg text-left transition-colors ${
                      selectedDevice?.ip_address === d.ip_address ? 'bg-slate-700' : 'hover:bg-slate-800'
                    }`}
                  >
                    <Icon className="w-4 h-4" style={{ color }} />
                    <div className="flex-1 min-w-0">
                      <div className="text-white text-sm font-mono truncate">{d.ip_address}</div>
                      <div className="text-xs text-slate-500 truncate">{d.hostname || d.vendor || 'Unknown'}</div>
                    </div>
                    {d.risk_score >= 70 && <AlertTriangle className="w-4 h-4 text-red-500" />}
                  </button>
                )
              })}
            </div>
          </div>
        </div>
      </div>

      {selectedDevice && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedDevice(null)}>
          <div className="glass-panel rounded-xl p-6 max-w-md w-full mx-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-semibold text-white">Device Details</h4>
              <button onClick={() => setSelectedDevice(null)} className="text-slate-400 hover:text-white">&times;</button>
            </div>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-slate-400">IP Address</span>
                <span className="text-white font-mono">{selectedDevice.ip_address}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">MAC Address</span>
                <span className="text-white font-mono">{selectedDevice.mac_address || 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Hostname</span>
                <span className="text-white">{selectedDevice.hostname || 'Unknown'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Vendor</span>
                <span className="text-white">{selectedDevice.vendor || 'Unknown'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Risk Score</span>
                <span className={selectedDevice.risk_score >= 70 ? 'text-red-400' : selectedDevice.risk_score >= 40 ? 'text-yellow-400' : 'text-green-400'}>
                  {selectedDevice.risk_score || 0}/100
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Status</span>
                <span className={selectedDevice.is_blocked ? 'text-red-400' : selectedDevice.is_trusted ? 'text-green-400' : 'text-blue-400'}>
                  {selectedDevice.is_blocked ? 'Blocked' : selectedDevice.is_trusted ? 'Trusted' : 'Normal'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Last Seen</span>
                <span className="text-white text-sm">{selectedDevice.last_seen ? new Date(selectedDevice.last_seen).toLocaleString() : 'N/A'}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
