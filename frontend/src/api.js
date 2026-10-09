import axios from 'axios'

const API = axios.create({ baseURL: import.meta.env.VITE_API_URL || '/api' })

// har request me token auto-attach
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('ti_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// 401 (token expire/invalid) -> logout
API.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response && err.response.status === 401) {
      localStorage.removeItem('ti_token')
      window.location.reload()
    }
    return Promise.reject(err)
  }
)

export const login = (username, password, otp) =>
  API.post('/login', { username, password, otp }).then(r => r.data)
export const getAuthConfig = () => API.get('/auth/config').then(r => r.data)

export const getStats        = ()       => API.get('/stats').then(r => r.data)
export const getHealth       = ()       => API.get('/health').then(r => r.data)
export const getAutomation   = ()       => API.get('/automation').then(r => r.data)
export const setAutomation   = (enabled) => API.post('/automation', { enabled }).then(r => r.data)
export const getIOCs         = (params) => API.get('/iocs', { params }).then(r => r.data)
export const getRecurring    = ()       => API.get('/iocs/recurring').then(r => r.data)
export const getIOCDetail    = (value)  => API.get(`/ioc/${encodeURIComponent(value)}`).then(r => r.data)
export const getCVEs         = (params) => API.get('/cves', { params }).then(r => r.data)
export const getCVEDetail    = (cveId)  => API.get(`/cve/${encodeURIComponent(cveId)}`).then(r => r.data)
export const getAPT          = ()       => API.get('/apt').then(r => r.data)
export const getAPTDetail    = (name)   => API.get(`/apt/${encodeURIComponent(name)}`).then(r => r.data)
export const getCorrelationSummary = () => API.get('/correlations/summary').then(r => r.data)
export const getCorrelationClusters = (params) => API.get('/correlations/clusters', { params }).then(r => r.data)
export const getMalwareCorrelation = (name) => API.get(`/correlations/malware/${encodeURIComponent(name)}`).then(r => r.data)
export const getAttackOverview = (params) => API.get('/attack/overview', { params }).then(r => r.data)
export const investigateEntity = (entity_type, value) => API.post('/investigate', { entity_type, value }).then(r => r.data)
export const getSIEMOverview = () => API.get('/siem/overview').then(r => r.data)
export const getSIEMEvent = (id) => API.get(`/siem/events/${id}`).then(r => r.data)
export const getArticles     = ()       => API.get('/articles').then(r => r.data)
export const getIOCTypeChart = ()       => API.get('/charts/ioc-types').then(r => r.data)
export const getSeverityChart= ()       => API.get('/charts/severity').then(r => r.data)
export const sendChatMessage = (question) => API.post('/chat', { question }).then(r => r.data)

export default API
