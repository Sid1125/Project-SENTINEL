import axios from 'axios'

export const API_URL = 'http://localhost:8000'
export const AUTH_STORAGE_KEY = 'sentinel.operatorToken'
export const AUTH_HEADER = 'X-Sentinel-Token'

const api = axios.create()

api.interceptors.request.use((config) => {
  const token = localStorage.getItem(AUTH_STORAGE_KEY)
  if (token) {
    config.headers = config.headers || {}
    config.headers[AUTH_HEADER] = token
  }
  return config
})

export const getStoredAuthToken = () => localStorage.getItem(AUTH_STORAGE_KEY) || ''

export const setStoredAuthToken = (token) => {
  if (token) {
    localStorage.setItem(AUTH_STORAGE_KEY, token)
    return
  }
  localStorage.removeItem(AUTH_STORAGE_KEY)
}

export const getWebSocketUrl = () => {
  try {
    const apiUrl = new URL(API_URL, window.location.origin)
    const wsUrl = new URL(apiUrl.origin)
    wsUrl.protocol = apiUrl.protocol === 'https:' ? 'wss:' : 'ws:'
    wsUrl.pathname = '/ws'
    return wsUrl.toString()
  } catch {
    return 'ws://localhost:8000/ws'
  }
}

export default api
