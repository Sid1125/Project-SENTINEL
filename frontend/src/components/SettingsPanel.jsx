import { useEffect, useState } from 'react'
import { Settings, Database, Cpu, Shield, Bell, Wifi, Save, RefreshCw, Lock, CheckCircle } from 'lucide-react'
import api, { API_URL, getStoredAuthToken, setStoredAuthToken } from '../lib/api'

export default function SettingsPanel() {
  const [settings, setSettings] = useState({
    llm_host: 'http://localhost:11434',
    llm_model: 'phi',
    scan_timeout: 30,
    auto_scan_interval: 1800,
    alert_notifications: true,
    auto_block_critical: true,
    auto_quarantine: false,
    notify_on_high: true,
    traffic_interface: 'auto',
    traffic_autostart: false,
    dns_sinkhole_enabled: false,
    dns_sinkhole_redirect_ip: '0.0.0.0',
    dns_blocked_domains: [],
    enforcement_mode: 'active',
    containment_allowed_segments: ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
    containment_allowed_destinations: [],
    containment_segments: ['users:192.168.1.0/24', 'iot:192.168.50.0/24', 'guest:192.168.75.0/24'],
    containment_segment_policies: ['users:restricted_network', 'iot:segment_isolation:192.168.1.1,8.8.8.8', 'guest:full_isolation'],
    containment_segment_conditions: [
      'iot:critical_ports:critical_service_isolation',
      'guest:trusted_device:restricted_network',
      'users:failed_logins:defensive_lockdown',
      'iot:scan_burst:full_isolation'
    ],
    containment_segment_thresholds: [
      'users:failed_logins:3:600:defensive_lockdown',
      'iot:port_scan_pattern:2:600:full_isolation'
    ],
    operator_token: getStoredAuthToken()
  })

  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(true)
  const [authConfig, setAuthConfig] = useState({ enabled: false, header: 'X-Sentinel-Token', token_hint: '', configured_roles: [] })
  const [authStatus, setAuthStatus] = useState(null)

  useEffect(() => {
    const loadSettings = async () => {
      try {
        const [authRes, configRes] = await Promise.all([
          api.get(`${API_URL}/api/v1/auth/config`),
          api.get(`${API_URL}/api/v1/config`),
        ])
        setAuthConfig(authRes.data)
        setSettings((current) => ({
          ...current,
          ...configRes.data.settings,
          operator_token: getStoredAuthToken(),
        }))
      } catch (err) {
        console.error('Failed to fetch settings:', err)
      } finally {
        setLoading(false)
      }
    }

    loadSettings()
  }, [])

  const handleSave = async () => {
    try {
      await api.put(`${API_URL}/api/v1/config`, {
        llm_host: settings.llm_host,
        llm_model: settings.llm_model,
        scan_timeout: settings.scan_timeout,
        auto_scan_interval: settings.auto_scan_interval,
        alert_notifications: settings.alert_notifications,
        auto_block_critical: settings.auto_block_critical,
        auto_quarantine: settings.auto_quarantine,
        notify_on_high: settings.notify_on_high,
        traffic_interface: settings.traffic_interface,
        traffic_autostart: settings.traffic_autostart,
        dns_sinkhole_enabled: settings.dns_sinkhole_enabled,
        dns_sinkhole_redirect_ip: settings.dns_sinkhole_redirect_ip,
        dns_blocked_domains: settings.dns_blocked_domains,
        enforcement_mode: settings.enforcement_mode,
        containment_allowed_segments: settings.containment_allowed_segments,
        containment_allowed_destinations: settings.containment_allowed_destinations,
        containment_segments: settings.containment_segments,
        containment_segment_policies: settings.containment_segment_policies,
        containment_segment_conditions: settings.containment_segment_conditions,
        containment_segment_thresholds: settings.containment_segment_thresholds,
      })
      setStoredAuthToken(settings.operator_token.trim())
      setSaved(true)
      setAuthStatus(null)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to save settings:', err)
    }
  }

  const verifyToken = async () => {
    try {
      setStoredAuthToken(settings.operator_token.trim())
      const res = await api.get(`${API_URL}/api/v1/auth/verify`)
      setAuthStatus(res.data)
    } catch (err) {
      setAuthStatus({
        authenticated: false,
        enabled: authConfig.enabled,
      })
    }
  }

  const sections = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'auth', label: 'Authentication', icon: Lock },
    { id: 'database', label: 'Database', icon: Database },
    { id: 'ai', label: 'AI/NLP', icon: Cpu },
    { id: 'scanning', label: 'Scanning', icon: Wifi },
    { id: 'defense', label: 'Defense', icon: Shield },
    { id: 'notifications', label: 'Notifications', icon: Bell },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-white">System Settings</h3>
        <p className="text-sm text-slate-400">Configure SENTINEL platform options</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="glass-panel rounded-xl p-4">
          <h4 className="font-medium text-white mb-4">Settings Categories</h4>
          <ul className="space-y-1">
            {sections.map(section => (
              <li key={section.id}>
                <button className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-slate-400 hover:bg-slate-800 hover:text-white transition-colors">
                  <section.icon className="w-4 h-4" />
                  {section.label}
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div className="lg:col-span-3 glass-panel rounded-xl p-6">
          <div className="space-y-6">
            <div>
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Lock className="w-5 h-5 text-sentinel-400" />
                Operator Authentication
              </h4>
              <div className="space-y-4">
                <div className="rounded-lg border border-slate-700 bg-slate-800/60 p-4 text-sm text-slate-300">
                  <div className="flex items-center justify-between gap-4">
                    <span>Backend auth status</span>
                    <span className={authConfig.enabled ? 'text-yellow-400' : 'text-green-400'}>
                      {authConfig.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                  <div className="mt-2 text-xs text-slate-500">
                    Header: {authConfig.header}
                    {authConfig.token_hint ? ` | Token hint: ${authConfig.token_hint}` : ''}
                    {authConfig.configured_roles?.length ? ` | Roles: ${authConfig.configured_roles.join(', ')}` : ''}
                  </div>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Local Operator Token</label>
                  <input
                    type="password"
                    value={settings.operator_token}
                    onChange={(e) => setSettings({ ...settings, operator_token: e.target.value })}
                    placeholder="Enter the token from SENTINEL_AUTH_TOKEN"
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={verifyToken}
                    className="sentinel-btn bg-slate-700 hover:bg-slate-600 text-white flex items-center gap-2"
                  >
                    <RefreshCw className="w-4 h-4" />
                    Verify Token
                  </button>
                  {authStatus && (
                    <div className={`flex items-center gap-2 text-sm ${authStatus.authenticated ? 'text-green-400' : 'text-red-400'}`}>
                      <CheckCircle className="w-4 h-4" />
                      {authStatus.authenticated
                        ? `Token verified${authStatus.role ? ` as ${authStatus.role}` : ''}`
                        : authStatus.enabled
                          ? 'Token rejected'
                          : 'Auth disabled on backend'}
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div>
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Cpu className="w-5 h-5 text-sentinel-400" />
                AI/NLP Configuration
              </h4>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-2">LLM Host</label>
                  <input
                    type="text"
                    value={settings.llm_host}
                    onChange={(e) => setSettings({...settings, llm_host: e.target.value})}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">LLM Model</label>
                  <select
                    value={settings.llm_model}
                    onChange={(e) => setSettings({...settings, llm_model: e.target.value})}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  >
                    <option value="phi:latest">Phi</option>
                    <option value="llama2">LLaMA2</option>
                    <option value="mistral">Mistral</option>
                  </select>
                </div>
              </div>
            </div>

            <div>
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Wifi className="w-5 h-5 text-sentinel-400" />
                Scanning Options
              </h4>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Scan Timeout (seconds)</label>
                  <input
                    type="number"
                    value={settings.scan_timeout}
                    onChange={(e) => setSettings({...settings, scan_timeout: parseInt(e.target.value)})}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Auto Scan Interval (seconds)</label>
                  <input
                    type="number"
                    value={settings.auto_scan_interval}
                    onChange={(e) => setSettings({...settings, auto_scan_interval: parseInt(e.target.value)})}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Preferred Capture Interface</label>
                  <input
                    type="text"
                    value={settings.traffic_interface}
                    onChange={(e) => setSettings({...settings, traffic_interface: e.target.value || 'auto'})}
                    placeholder="auto"
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                </div>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.traffic_autostart}
                    onChange={(e) => setSettings({...settings, traffic_autostart: e.target.checked})}
                    className="w-4 h-4 rounded bg-slate-800 border-slate-600 text-sentinel-600 focus:ring-sentinel-500"
                  />
                  <span className="text-white">Auto-start packet capture at launch</span>
                </label>
              </div>
            </div>

            <div>
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Shield className="w-5 h-5 text-sentinel-400" />
                Defense Options
              </h4>
              <div className="space-y-3">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.auto_block_critical}
                    onChange={(e) => setSettings({...settings, auto_block_critical: e.target.checked})}
                    className="w-4 h-4 rounded bg-slate-800 border-slate-600 text-sentinel-600 focus:ring-sentinel-500"
                  />
                  <span className="text-white">Auto-block high-risk devices</span>
                </label>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.auto_quarantine}
                    onChange={(e) => setSettings({...settings, auto_quarantine: e.target.checked})}
                    className="w-4 h-4 rounded bg-slate-800 border-slate-600 text-sentinel-600 focus:ring-sentinel-500"
                  />
                  <span className="text-white">Auto-quarantine elevated-risk devices</span>
                </label>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.alert_notifications}
                    onChange={(e) => setSettings({...settings, alert_notifications: e.target.checked})}
                    className="w-4 h-4 rounded bg-slate-800 border-slate-600 text-sentinel-600 focus:ring-sentinel-500"
                  />
                  <span className="text-white">Enable alert notifications</span>
                </label>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.notify_on_high}
                    onChange={(e) => setSettings({...settings, notify_on_high: e.target.checked})}
                    className="w-4 h-4 rounded bg-slate-800 border-slate-600 text-sentinel-600 focus:ring-sentinel-500"
                  />
                  <span className="text-white">Create alerts for high-risk detections</span>
                </label>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Enforcement Mode</label>
                  <select
                    value={settings.enforcement_mode}
                    onChange={(e) => setSettings({...settings, enforcement_mode: e.target.value})}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  >
                    <option value="active">Active enforcement</option>
                    <option value="dry_run">Dry run only</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Named Network Segments</label>
                  <textarea
                    value={(settings.containment_segments || []).join('\n')}
                    onChange={(e) => setSettings({
                      ...settings,
                      containment_segments: e.target.value
                        .split(/\r?\n/)
                        .map((entry) => entry.trim())
                        .filter(Boolean)
                    })}
                    rows={4}
                    placeholder={'users:192.168.1.0/24\niot:192.168.50.0/24'}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                  <p className="mt-1 text-xs text-slate-500">Format: `name:cidr`. Segment isolation keeps a device inside its matched segment.</p>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Per-Segment Containment Policies</label>
                  <textarea
                    value={(settings.containment_segment_policies || []).join('\n')}
                    onChange={(e) => setSettings({
                      ...settings,
                      containment_segment_policies: e.target.value
                        .split(/\r?\n/)
                        .map((entry) => entry.trim())
                        .filter(Boolean)
                    })}
                    rows={4}
                    placeholder={'iot:segment_isolation:192.168.1.1,8.8.8.8\nguest:full_isolation'}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                  <p className="mt-1 text-xs text-slate-500">Format: `segment:profile[:allowed_destination1,allowed_destination2]`.</p>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Per-Segment Behavior Conditions</label>
                  <textarea
                    value={(settings.containment_segment_conditions || []).join('\n')}
                    onChange={(e) => setSettings({
                      ...settings,
                      containment_segment_conditions: e.target.value
                        .split(/\r?\n/)
                        .map((entry) => entry.trim())
                        .filter(Boolean)
                    })}
                    rows={4}
                    placeholder={'iot:critical_ports:critical_service_isolation\nguest:trusted_device:restricted_network\nusers:failed_logins:defensive_lockdown'}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                  <p className="mt-1 text-xs text-slate-500">Format: `segment:condition:profile`. Conditions supported: `critical_ports`, `high_risk`, `trusted_device`, `failed_logins`, `scan_burst`, `malicious_request`, `honeypot_activity`.</p>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Per-Segment Telemetry Thresholds</label>
                  <textarea
                    value={(settings.containment_segment_thresholds || []).join('\n')}
                    onChange={(e) => setSettings({
                      ...settings,
                      containment_segment_thresholds: e.target.value
                        .split(/\r?\n/)
                        .map((entry) => entry.trim())
                        .filter(Boolean)
                    })}
                    rows={4}
                    placeholder={'users:failed_logins:3:600:defensive_lockdown\niot:port_scan_pattern:2:600:full_isolation'}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                  <p className="mt-1 text-xs text-slate-500">Format: `segment:trigger:count:window_seconds:profile`.</p>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Allowed Network Segments During Restricted Containment</label>
                  <textarea
                    value={(settings.containment_allowed_segments || []).join('\n')}
                    onChange={(e) => setSettings({
                      ...settings,
                      containment_allowed_segments: e.target.value
                        .split(/\r?\n|,/)
                        .map((entry) => entry.trim())
                        .filter(Boolean)
                    })}
                    rows={4}
                    placeholder={'192.168.0.0/16\n10.0.0.0/8'}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                  <p className="mt-1 text-xs text-slate-500">One CIDR per line. Restricted containment will allow these segments before denying other routed traffic.</p>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Always-Allowed Destinations During Restricted Containment</label>
                  <textarea
                    value={(settings.containment_allowed_destinations || []).join('\n')}
                    onChange={(e) => setSettings({
                      ...settings,
                      containment_allowed_destinations: e.target.value
                        .split(/\r?\n|,/)
                        .map((entry) => entry.trim())
                        .filter(Boolean)
                    })}
                    rows={3}
                    placeholder={'192.168.1.10\n8.8.8.8'}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sentinel-500"
                  />
                  <p className="mt-1 text-xs text-slate-500">Optional IPs or CIDRs that remain reachable during restricted containment.</p>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-[#1e293b]">
              <button
                onClick={handleSave}
                disabled={loading}
                className="sentinel-btn sentinel-btn-primary flex items-center gap-2"
              >
                <Save className="w-4 h-4" />
                {loading ? 'Loading...' : saved ? 'Saved!' : 'Save Settings'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
