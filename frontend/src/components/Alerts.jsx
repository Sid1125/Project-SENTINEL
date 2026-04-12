import { useState, useEffect } from 'react'
import { AlertTriangle, Info, AlertCircle, CheckCircle, RefreshCw, Filter } from 'lucide-react'
import api, { API_URL } from '../lib/api'

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    fetchAlerts()
  }, [])

  const fetchAlerts = async () => {
    try {
      const res = await api.get(`${API_URL}/api/v1/alerts`)
      setAlerts(res.data.alerts || [])
    } catch (err) {
      console.error('Failed to fetch alerts:', err)
    } finally {
      setLoading(false)
    }
  }

  const resolveAlert = async (alertId) => {
    try {
      await api.post(`${API_URL}/api/v1/alerts/${alertId}/resolve`)
      fetchAlerts()
    } catch (err) {
      console.error('Failed to resolve alert:', err)
    }
  }

  const getSeverityIcon = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return <AlertCircle className="w-5 h-5 text-red-400" />
      case 'high': return <AlertTriangle className="w-5 h-5 text-orange-400" />
      case 'medium': return <AlertTriangle className="w-5 h-5 text-yellow-400" />
      default: return <Info className="w-5 h-5 text-blue-400" />
    }
  }

  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'border-red-500/30 bg-red-500/5'
      case 'high': return 'border-orange-500/30 bg-orange-500/5'
      case 'medium': return 'border-yellow-500/30 bg-yellow-500/5'
      default: return 'border-blue-500/30 bg-blue-500/5'
    }
  }

  const filteredAlerts = filter === 'all' 
    ? alerts 
    : filter === 'resolved' 
      ? alerts.filter(a => a.is_resolved)
      : alerts.filter(a => !a.is_resolved)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white">Security Alerts</h3>
          <p className="text-sm text-slate-400">Network threat notifications and events</p>
        </div>
        <div className="flex gap-3">
          <div className="flex items-center gap-2 bg-slate-800 rounded-lg p-1">
            <Filter className="w-4 h-4 text-slate-400" />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="bg-transparent text-slate-300 text-sm focus:outline-none"
            >
              <option value="all">All</option>
              <option value="active">Active</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
          <button
            onClick={fetchAlerts}
            className="sentinel-btn bg-slate-700 hover:bg-slate-600 text-white flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      <div className="glass-panel rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-400">
            <RefreshCw className="w-8 h-8 mx-auto mb-2 animate-spin" />
            Loading alerts...
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="p-8 text-center text-slate-400">
            <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-500" />
            <p>No alerts to display</p>
          </div>
        ) : (
          <div className="divide-y divide-[#1e293b]">
            {filteredAlerts.map((alert, idx) => (
              <div key={idx} className={`p-5 border-l-2 ${getSeverityClass(alert.severity)}`}>
                <div className="flex items-start gap-4">
                  <div className="mt-1">
                    {getSeverityIcon(alert.severity)}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h4 className="font-medium text-white">{alert.title}</h4>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        alert.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                        alert.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        alert.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-blue-500/20 text-blue-400'
                      }`}>
                        {alert.severity?.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm text-slate-400 mt-1">{alert.message}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                      {alert.source_ip && <span>Source: {alert.source_ip}</span>}
                      {alert.created_at && <span>{new Date(alert.created_at).toLocaleString()}</span>}
                    </div>
                  </div>
                  {!alert.is_resolved && (
                    <button 
                      onClick={() => resolveAlert(alert.id)}
                      className="text-sm text-sentinel-400 hover:text-sentinel-300"
                    >
                      Resolve
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
