import { useState, useEffect } from 'react'
import { Wifi, Search, Shield, Ban, ChevronRight, RefreshCw, AlertTriangle, Unlock } from 'lucide-react'
import api, { API_URL } from '../lib/api'

const formatDecisionTrace = (trace) => (Array.isArray(trace) ? trace : [])
  .map((entry) => entry?.detail || `${entry?.stage || 'decision'} -> ${entry?.outcome || 'unknown'}`)
  .filter(Boolean)

export default function Devices() {
  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [quarantineProfile, setQuarantineProfile] = useState('restricted_network')
  const [defenseStatus, setDefenseStatus] = useState(null)

  const quarantineProfileLabels = {
    restricted_network: 'Restricted network',
    segment_isolation: 'Segment isolation',
    full_isolation: 'Full isolation',
    critical_service_isolation: 'Critical services only',
    defensive_lockdown: 'Defensive lockdown',
  }

  const availableQuarantineProfiles = defenseStatus?.quarantine_profiles?.length
    ? defenseStatus.quarantine_profiles
    : ['restricted_network', 'full_isolation']

  useEffect(() => {
    fetchDevices()
  }, [])

  const fetchDevices = async () => {
    try {
      const [devicesRes, defenseStatusRes] = await Promise.all([
        api.get(`${API_URL}/api/v1/devices`),
        api.get(`${API_URL}/api/v1/defense/status`).catch(() => ({ data: {} })),
      ])
      setDevices(devicesRes.data.devices || [])
      setDefenseStatus(defenseStatusRes.data || {})
    } catch (err) {
      console.error('Failed to fetch devices:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleScan = async () => {
    if (scanning) return
    setScanning(true)
    try {
      await api.post(`${API_URL}/api/v1/scan/network`)
      fetchDevices()
    } catch (err) {
      console.error('Scan failed:', err)
    } finally {
      setScanning(false)
    }
  }

  const handleDeviceClick = (device) => {
    setSelectedDevice(device)
  }

  const scanDevicePorts = async (ip) => {
    setSelectedDevice({ ...selectedDevice, ip_address: ip, scanning: true })
    try {
      const res = await api.post(`${API_URL}/api/v1/scan/ports?target=${encodeURIComponent(ip)}&ports=1-1000`)
      setSelectedDevice({ 
        ...selectedDevice, 
        ports: res.data.ports || [],
        analysis: res.data.analysis,
        scanning: false
      })
    } catch (err) {
      console.error('Port scan failed:', err)
      setSelectedDevice({ ...selectedDevice, scanning: false })
    }
  }

  const handleTrustDevice = async (ip) => {
    try {
      await api.put(`${API_URL}/api/v1/device`, {
        ip_address: ip,
        is_trusted: true,
        is_blocked: false
      })
      fetchDevices()
    } catch (err) {
      console.error('Failed to trust device:', err)
    }
  }

  const handleBlockDevice = async (ip) => {
    try {
      await api.post(`${API_URL}/api/v1/defense/block/${ip}`)
      fetchDevices()
    } catch (err) {
      console.error('Failed to block device:', err)
    }
  }

  const handleQuarantineDevice = async (ip) => {
    try {
      const scope = quarantineProfile === 'full_isolation'
        ? 'all_traffic'
        : quarantineProfile === 'segment_isolation'
          ? 'network_segment'
        : quarantineProfile === 'critical_service_isolation'
          ? 'critical_services'
          : 'lan_traffic'
      await api.post(`${API_URL}/api/v1/defense/quarantine/${ip}`, null, {
        params: { profile: quarantineProfile, scope },
      })
      fetchDevices()
    } catch (err) {
      console.error('Failed to quarantine device:', err)
    }
  }

  const handleReleaseContainment = async (device) => {
    try {
      if (device.status === 'quarantined') {
        await api.post(`${API_URL}/api/v1/defense/unquarantine/${device.ip_address}`)
      } else if (device.is_blocked) {
        await api.post(`${API_URL}/api/v1/defense/unblock/${device.ip_address}`)
      }
      fetchDevices()
    } catch (err) {
      console.error('Failed to release containment:', err)
    }
  }

  const getRiskClass = (score) => {
    if (score >= 70) return 'risk-critical'
    if (score >= 40) return 'risk-high'
    if (score >= 20) return 'risk-medium'
    return 'risk-low'
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white">Network Devices</h3>
          <p className="text-sm text-slate-400">Discovered devices on your network</p>
        </div>
        <button
          onClick={handleScan}
          disabled={scanning}
          className="sentinel-btn sentinel-btn-primary flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
          {scanning ? 'Scanning...' : 'Scan Network'}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 glass-panel rounded-xl overflow-hidden">
          <div className="p-4 border-b border-[#1e293b]">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search devices..."
                className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-sentinel-500"
              />
            </div>
          </div>

          <div className="divide-y divide-[#1e293b]">
            {loading ? (
              <div className="p-8 text-center text-slate-400">
                <RefreshCw className="w-8 h-8 mx-auto mb-2 animate-spin" />
                Loading devices...
              </div>
            ) : devices.length === 0 ? (
              <div className="p-8 text-center text-slate-400">
                <Wifi className="w-8 h-8 mx-auto mb-2" />
                No devices found. Run a network scan to discover devices.
              </div>
            ) : (
              devices.map((device, idx) => (
                <div
                  key={idx}
                  onClick={() => handleDeviceClick(device)}
                  className="p-4 hover:bg-slate-800/50 cursor-pointer flex items-center justify-between transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 bg-slate-700 rounded-lg flex items-center justify-center">
                      <Wifi className="w-5 h-5 text-sentinel-400" />
                    </div>
                    <div>
                      <div className="font-medium text-white">{device.ip_address}</div>
                      <div className="text-sm text-slate-400">
                        {device.hostname || 'Unknown'} - {device.vendor || 'Unknown vendor'}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {device.is_trusted && (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-green-500/20 text-green-400">
                        Trusted
                      </span>
                    )}
                    {device.is_blocked && (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-red-500/20 text-red-400">
                        Blocked
                      </span>
                    )}
                    {device.status === 'quarantined' && (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-yellow-500/20 text-yellow-300">
                        Quarantined
                      </span>
                    )}
                    {device.risk_score > 0 && (
                      <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getRiskClass(device.risk_score)}`}>
                        Risk: {device.risk_score}
                      </span>
                    )}
                    <ChevronRight className="w-5 h-5 text-slate-500" />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="glass-panel rounded-xl p-6">
          <h4 className="text-lg font-semibold text-white mb-4">Device Details</h4>
          
          {!selectedDevice ? (
            <div className="text-center text-slate-400 py-8">
              <Wifi className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>Select a device to view details</p>
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="text-xs text-slate-500 uppercase">IP Address</label>
                <div className="text-white font-mono">{selectedDevice.ip_address}</div>
              </div>
              
              <div>
                <label className="text-xs text-slate-500 uppercase">MAC Address</label>
                <div className="text-white font-mono">{selectedDevice.mac_address || 'Unknown'}</div>
              </div>
              
              <div>
                <label className="text-xs text-slate-500 uppercase">Hostname</label>
                <div className="text-white">{selectedDevice.hostname || 'Unknown'}</div>
              </div>
              
              <div>
                <label className="text-xs text-slate-500 uppercase">Vendor</label>
                <div className="text-white">{selectedDevice.vendor || 'Unknown'}</div>
              </div>

              <div>
                <label className="text-xs text-slate-500 uppercase">Status</label>
                <div className="text-white">
                  {selectedDevice.status || 'Unknown'}
                </div>
              </div>

              {selectedDevice.containment?.active && (
                <div className="rounded-lg border border-yellow-600/30 bg-yellow-500/10 p-4">
                  <div className="text-sm font-medium text-yellow-300">Containment Active</div>
                  <div className="mt-1 text-sm text-slate-200">
                    Profile: {quarantineProfileLabels[selectedDevice.containment.profile] || selectedDevice.containment.profile || 'restricted_network'}
                  </div>
                  <div className="text-sm text-slate-300">
                    Scope: {selectedDevice.containment.scope || 'lan_traffic'}
                  </div>
                  {selectedDevice.containment.ports?.length > 0 && (
                    <div className="text-sm text-slate-300">
                      Protected ports: {selectedDevice.containment.ports.join(', ')}
                    </div>
                  )}
                  {selectedDevice.containment.allowed_networks?.length > 0 && (
                    <div className="text-sm text-slate-300">
                      Allowed segments: {selectedDevice.containment.allowed_networks.join(', ')}
                    </div>
                  )}
                  {selectedDevice.containment.segment_name && (
                    <div className="text-sm text-slate-300">
                      Segment: {selectedDevice.containment.segment_name}
                    </div>
                  )}
                  {selectedDevice.containment.policy_name && (
                    <div className="text-sm text-slate-300">
                      Policy: {selectedDevice.containment.policy_name}
                    </div>
                  )}
                  {selectedDevice.containment.condition_name && (
                    <div className="text-sm text-slate-300">
                      Condition: {selectedDevice.containment.condition_name}
                    </div>
                  )}
                  {selectedDevice.containment.allowed_destinations?.length > 0 && (
                    <div className="text-sm text-slate-300">
                      Allowed destinations: {selectedDevice.containment.allowed_destinations.join(', ')}
                    </div>
                  )}
                  {formatDecisionTrace(selectedDevice.containment.decision_trace).length > 0 && (
                    <div className="mt-2">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Decision trace</div>
                      <div className="mt-1 space-y-1">
                        {formatDecisionTrace(selectedDevice.containment.decision_trace).map((step, index) => (
                          <div key={`${step}-${index}`} className="text-xs text-slate-400">
                            {index + 1}. {step}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="text-xs text-slate-400 mt-2">
                    {selectedDevice.containment.reason || 'Device is under containment review.'}
                  </div>
                </div>
              )}

              <button
                onClick={(e) => { e.stopPropagation(); scanDevicePorts(selectedDevice.ip_address); }}
                className="w-full sentinel-btn sentinel-btn-primary flex items-center justify-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                Scan Ports
              </button>

              {selectedDevice.ports && selectedDevice.ports.length > 0 && (
                <div>
                  <label className="text-xs text-slate-500 uppercase">Open Ports</label>
                  <div className="space-y-1 mt-2">
                    {selectedDevice.ports.map((port, i) => (
                      <div key={i} className="flex items-center justify-between bg-slate-800 rounded px-3 py-2">
                        <span className="text-white font-mono">{port.port}/{port.protocol}</span>
                        <span className="text-slate-400 text-sm">{port.service}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedDevice.analysis && (
                <div className={`p-4 rounded-lg border ${getRiskClass(selectedDevice.analysis.risk_score)}`}>
                  <div className="text-sm font-medium">Risk Assessment</div>
                  <div className="text-2xl font-bold mt-1">{selectedDevice.analysis.risk_category?.toUpperCase()}</div>
                  <div className="text-sm mt-1">Score: {selectedDevice.analysis.risk_score}/100</div>
                  {selectedDevice.analysis.findings && selectedDevice.analysis.findings.length > 0 && (
                    <div className="mt-2 text-xs">
                      <div className="text-slate-400">Findings:</div>
                      {selectedDevice.analysis.findings.slice(0, 3).map((f, i) => (
                        <div key={i} className="text-slate-300">- {f.reasons?.[0] || f.risk_level}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div className="flex gap-2 pt-4">
                <button 
                  onClick={(e) => { e.stopPropagation(); handleTrustDevice(selectedDevice.ip_address); }}
                  className="flex-1 sentinel-btn bg-green-600/20 hover:bg-green-600/30 text-green-400 border border-green-600/30 flex items-center justify-center gap-2"
                >
                  <Shield className="w-4 h-4" />
                  Trust
                </button>
                <button 
                  onClick={(e) => { e.stopPropagation(); handleBlockDevice(selectedDevice.ip_address); }}
                  className="flex-1 sentinel-btn bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-600/30 flex items-center justify-center gap-2"
                >
                  <Ban className="w-4 h-4" />
                  Block
                </button>
              </div>
              <div className="flex gap-2">
                <select
                  value={quarantineProfile}
                  onChange={(e) => setQuarantineProfile(e.target.value)}
                  className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white"
                >
                  {availableQuarantineProfiles.map((profile) => (
                    <option key={profile} value={profile}>
                      {quarantineProfileLabels[profile] || profile}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex gap-2">
                <button 
                  onClick={(e) => { e.stopPropagation(); handleQuarantineDevice(selectedDevice.ip_address); }}
                  className="flex-1 sentinel-btn bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-300 border border-yellow-600/30 flex items-center justify-center gap-2"
                >
                  <AlertTriangle className="w-4 h-4" />
                  Quarantine
                </button>
                <button 
                  onClick={(e) => { e.stopPropagation(); handleReleaseContainment(selectedDevice); }}
                  className="flex-1 sentinel-btn bg-slate-700 hover:bg-slate-600 text-slate-100 border border-slate-600 flex items-center justify-center gap-2"
                >
                  <Unlock className="w-4 h-4" />
                  Release
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
