import { useState, useEffect, useRef } from 'react'
import { Send, Bot, User, Loader, Lightbulb } from 'lucide-react'
import api, { API_URL } from '../lib/api'

export default function NLPChat() {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Hello! I\'m your SENTINEL AI Assistant. You can ask me to:\n\n• "Scan my network" - Discover all devices\n• "Check for threats" - Analyze device vulnerabilities\n• "Scan 192.168.1.1" - Scan specific IP\n• "Show status" - View security overview\n\nWhat would you like me to do?' }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const messagesEnd = useRef(null)

  useEffect(() => {
    messagesEnd.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!input.trim()) return
    
    const userMessage = input.trim()
    setMessages(prev => [...prev, { role: 'user', content: userMessage }])
    setInput('')
    setLoading(true)
    
    try {
      const response = await api.post(`${API_URL}/api/v1/nlp/prompt`, { prompt: userMessage })
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: response.data.response || 'Task completed.' 
      }])
    } catch (err) {
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: 'Sorry, I encountered an error processing your request.' 
      }])
    } finally {
      setLoading(false)
    }
  }

  const suggestions = [
    'Scan my network',
    'Check for threats',
    'Show status',
    'Help'
  ]

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-white">AI Control Center</h3>
        <p className="text-sm text-slate-400">Natural language commands for security operations</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 glass-panel rounded-xl overflow-hidden flex flex-col" style={{ height: '600px' }}>
          <div className="p-4 border-b border-[#1e293b] bg-slate-800/50">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-sentinel-600/20 rounded-lg">
                <Bot className="w-5 h-5 text-sentinel-400" />
              </div>
              <div>
                <h4 className="font-medium text-white">SENTINEL Assistant</h4>
                <p className="text-xs text-slate-400">Powered by Phi-2 Local LLM</p>
              </div>
            </div>
          </div>

          <div className="flex-1 overflow-auto p-4 space-y-4">
            {messages.map((msg, idx) => (
              <div key={idx} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}>
                {msg.role === 'assistant' && (
                  <div className="w-8 h-8 bg-sentinel-600/20 rounded-full flex items-center justify-center flex-shrink-0">
                    <Bot className="w-4 h-4 text-sentinel-400" />
                  </div>
                )}
                <div className={`max-w-[70%] rounded-lg p-4 ${
                  msg.role === 'user' 
                    ? 'bg-sentinel-600 text-white' 
                    : 'bg-slate-800 text-slate-200'
                }`}>
                  <pre className="whitespace-pre-wrap font-sans text-sm">{msg.content}</pre>
                </div>
                {msg.role === 'user' && (
                  <div className="w-8 h-8 bg-slate-700 rounded-full flex items-center justify-center flex-shrink-0">
                    <User className="w-4 h-4 text-slate-300" />
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div className="flex gap-3">
                <div className="w-8 h-8 bg-sentinel-600/20 rounded-full flex items-center justify-center">
                  <Bot className="w-4 h-4 text-sentinel-400" />
                </div>
                <div className="bg-slate-800 rounded-lg p-4">
                  <Loader className="w-5 h-5 text-sentinel-400 animate-spin" />
                </div>
              </div>
            )}
            <div ref={messagesEnd} />
          </div>

          <form onSubmit={handleSubmit} className="p-4 border-t border-[#1e293b]">
            <div className="flex gap-3">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Type your command..."
                className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-sentinel-500"
              />
              <button
                type="submit"
                disabled={!input.trim() || loading}
                className="sentinel-btn sentinel-btn-primary px-6"
              >
                <Send className="w-5 h-5" />
              </button>
            </div>
          </form>
        </div>

        <div className="space-y-4">
          <div className="glass-panel rounded-xl p-5">
            <h4 className="font-medium text-white mb-4 flex items-center gap-2">
              <Lightbulb className="w-4 h-4 text-yellow-400" />
              Quick Commands
            </h4>
            <div className="space-y-2">
              {suggestions.map((suggestion, idx) => (
                <button
                  key={idx}
                  onClick={() => { setInput(suggestion); }}
                  className="w-full text-left px-4 py-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm transition-colors"
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </div>

          <div className="glass-panel rounded-xl p-5">
            <h4 className="font-medium text-white mb-3">Supported Commands</h4>
            <ul className="space-y-2 text-sm text-slate-400">
              <li>• Scan network</li>
              <li>• Scan [IP address]</li>
              <li>• Check threats</li>
              <li>• Block [IP]</li>
              <li>• Trust [IP]</li>
              <li>• Show status</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
