import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BarChart3,
  Bell,
  Download,
  Eye,
  FileText,
  Globe,
  Mail,
  Menu,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Trash2,
  UserRound,
  X,
} from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  BrowserRouter,
  Link,
  NavLink,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from 'react-router-dom'

const API_BASE = 'http://localhost:8000'
const riskPalette = {
  'Low Risk': '#34d399',
  'Medium Risk': '#fbbf24',
  'High Risk': '#f97316',
  'Critical Risk': '#ef4444',
}

const defaultDashboard = {
  total: 128,
  high_risk: 28,
  medium_risk: 34,
  low_risk: 66,
  recent_scans: [
    { id: 1, created_at: '2026-10-15T10:00:00Z', analysis_type: 'email', risk_score: 91, risk_level: 'Critical Risk' },
    { id: 2, created_at: '2026-10-15T09:40:00Z', analysis_type: 'url', risk_score: 67, risk_level: 'High Risk' },
    { id: 3, created_at: '2026-10-15T09:10:00Z', analysis_type: 'email', risk_score: 41, risk_level: 'Medium Risk' },
  ],
  risk_distribution: [
    { risk_level: 'Low Risk', total: 66 },
    { risk_level: 'Medium Risk', total: 34 },
    { risk_level: 'High Risk', total: 20 },
    { risk_level: 'Critical Risk', total: 8 },
  ],
  indicator_summary: [
    ['Urgent or Threatening Language', 21],
    ['Credential or Financial Request', 18],
    ['Suspicious Embedded URL', 14],
    ['Brand Impersonation in Content', 10],
  ],
}

async function apiRequest(endpoint, options = {}) {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(text || 'Request failed')
  }

  return response.json()
}

function formatDate(value) {
  if (!value) return 'Unknown'
  return new Date(value).toLocaleString([], {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

function className(...parts) {
  return parts.filter(Boolean).join(' ')
}

function getRiskStyle(level) {
  const palette = {
    'Low Risk': 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
    'Medium Risk': 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
    'High Risk': 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
    'Critical Risk': 'bg-red-500/15 text-red-300 border border-red-500/30',
  }
  return palette[level] || 'bg-slate-500/15 text-slate-300 border border-slate-500/30'
}

function getScoreTone(score) {
  if (score >= 80) return 'text-red-300'
  if (score >= 60) return 'text-orange-300'
  if (score >= 30) return 'text-amber-300'
  return 'text-emerald-300'
}

function DashboardPage() {
  const [metrics, setMetrics] = useState(defaultDashboard)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const response = await apiRequest('/api/dashboard')
        if (!cancelled) {
          const incoming = response.metrics || {}
          const hasData = (incoming.total || 0) > 0 || (incoming.recent_scans || []).length > 0 || (incoming.risk_distribution || []).length > 0
          setMetrics(hasData ? { ...defaultDashboard, ...incoming } : defaultDashboard)
          setLoading(false)
        }
      } catch (error) {
        if (!cancelled) setMetrics(defaultDashboard)
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => {
      cancelled = true
    }
  }, [])

  const chartData = useMemo(
    () => metrics.risk_distribution.map((item) => ({ ...item, fill: riskPalette[item.risk_level] })),
    [metrics.risk_distribution],
  )

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.22em] text-cyan-300">Threat overview</p>
          <h1 className="mt-2 text-3xl font-bold text-white md:text-4xl">Security dashboard</h1>
        </div>
        <div className="rounded-xl border border-cyan-500/20 bg-slate-900/70 px-3 py-2 text-sm text-slate-300">
          Demo data • Actual scan results saved in SQLite
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {[
          { label: 'Total analyzed', value: metrics.total, icon: BarChart3 },
          { label: 'High risk', value: metrics.high_risk, icon: ShieldX },
          { label: 'Medium risk', value: metrics.medium_risk, icon: AlertTriangle },
          { label: 'Low risk', value: metrics.low_risk, icon: ShieldCheck },
        ].map(({ label, value, icon: Icon }) => (
          <div key={label} className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
            <div className="flex items-center justify-between">
              <p className="text-sm text-slate-400">{label}</p>
              <Icon className="h-5 w-5 text-cyan-300" />
            </div>
            <div className="mt-4 text-3xl font-bold text-white">{loading ? '…' : value}</div>
          </div>
        ))}
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_0.9fr]">
        <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-xl font-semibold text-white">Risk distribution</h2>
            <div className="text-sm text-slate-400">Last 30 days</div>
          </div>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={chartData} dataKey="total" nameKey="risk_level" innerRadius={55} outerRadius={92} paddingAngle={3}>
                  {chartData.map((entry) => (
                    <Cell key={entry.risk_level} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip formatter={(value) => [`${value} scans`, 'Count']} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {chartData.map((entry) => (
              <span key={entry.risk_level} className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-200">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: entry.fill }} />
                {entry.risk_level}
              </span>
            ))}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
          <h2 className="text-xl font-semibold text-white">Common indicators</h2>
          <div className="mt-4 space-y-3">
            {(metrics.indicator_summary || []).map(([name, count]) => (
              <div key={name} className="rounded-xl border border-slate-700 bg-slate-950/60 p-3">
                <div className="flex items-center justify-between gap-3 text-sm">
                  <span className="text-slate-200">{name}</span>
                  <span className="font-semibold text-cyan-300">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.4fr_0.9fr]">
        <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
          <h2 className="text-xl font-semibold text-white">Recent scan history</h2>
          <div className="mt-4 overflow-hidden rounded-xl border border-slate-700">
            <table className="min-w-full divide-y divide-slate-700 text-left text-sm">
              <thead className="bg-slate-950/80 text-slate-300">
                <tr>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Risk</th>
                  <th className="px-3 py-2">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 bg-slate-900/60">
                {(metrics.recent_scans || []).map((scan) => (
                  <tr key={scan.id}>
                    <td className="px-3 py-2 text-slate-200">{scan.analysis_type}</td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${getRiskStyle(scan.risk_level)}`}>
                        {scan.risk_level}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-400">{formatDate(scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
          <h2 className="text-xl font-semibold text-white">Quick actions</h2>
          <div className="mt-4 space-y-3">
            <Link to="/email" className="flex items-center justify-between rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-3 text-left text-cyan-100 transition hover:bg-cyan-500/20">
              <span className="flex items-center gap-3"><Mail className="h-5 w-5" /> Analyze email</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link to="/url" className="flex items-center justify-between rounded-xl border border-violet-500/30 bg-violet-500/10 px-4 py-3 text-left text-violet-100 transition hover:bg-violet-500/20">
              <span className="flex items-center gap-3"><Globe className="h-5 w-5" /> Analyze URL</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link to="/reports" className="flex items-center justify-between rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-left text-emerald-100 transition hover:bg-emerald-500/20">
              <span className="flex items-center gap-3"><FileText className="h-5 w-5" /> View reports</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}

function EmailAnalyzerPage() {
  const navigate = useNavigate()
  const [form, setForm] = useState({
    subject: 'Urgent: Account verification required',
    sender_email: 'security@paypa1-update.com',
    display_name: 'PayPal Security Team',
    reply_to: 'noreply@mailer.com',
    message: 'Your account has been suspended. Please verify immediately to avoid permanent restrictions. Use the secure link below and confirm your OTP before 9:00 PM.',
    manual_url: 'https://bit.ly/verify-paypal-secure-login',
    attachment_hint: 'invoice.exe',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(event) {
    event.preventDefault()
    setLoading(true)
    setError('')

    try {
      const result = await apiRequest('/api/analyze/email', {
        method: 'POST',
        body: JSON.stringify(form),
      })
      navigate('/analysis', { state: { analysis: result } })
    } catch (err) {
      setError(err.message || 'Unable to analyze the email.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.22em] text-cyan-300">Communication safety</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Email and message analyzer</h1>
      </div>

      <form onSubmit={handleSubmit} className="grid gap-5 rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow md:grid-cols-2">
        <label className="space-y-2">
          <span className="text-sm text-slate-300">Email subject</span>
          <input value={form.subject} onChange={(event) => setForm({ ...form, subject: event.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-400" />
        </label>
        <label className="space-y-2">
          <span className="text-sm text-slate-300">Sender email</span>
          <input value={form.sender_email} onChange={(event) => setForm({ ...form, sender_email: event.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-400" />
        </label>
        <label className="space-y-2">
          <span className="text-sm text-slate-300">Display name</span>
          <input value={form.display_name} onChange={(event) => setForm({ ...form, display_name: event.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-400" />
        </label>
        <label className="space-y-2">
          <span className="text-sm text-slate-300">Reply-to</span>
          <input value={form.reply_to} onChange={(event) => setForm({ ...form, reply_to: event.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-400" />
        </label>
        <label className="space-y-2 md:col-span-2">
          <span className="text-sm text-slate-300">Message body</span>
          <textarea rows="6" value={form.message} onChange={(event) => setForm({ ...form, message: event.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-400" />
        </label>
        <label className="space-y-2 md:col-span-2">
          <span className="text-sm text-slate-300">Manual URL (optional)</span>
          <input value={form.manual_url} onChange={(event) => setForm({ ...form, manual_url: event.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-400" />
        </label>
        <label className="space-y-2 md:col-span-2">
          <span className="text-sm text-slate-300">Attachment note</span>
          <input value={form.attachment_hint} onChange={(event) => setForm({ ...form, attachment_hint: event.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-400" />
        </label>

        {error && <div className="md:col-span-2 rounded-xl border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}

        <div className="md:col-span-2 flex justify-end">
          <button type="submit" disabled={loading} className="rounded-xl bg-cyan-500 px-5 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60">
            {loading ? 'Analyzing...' : 'Analyze email'}
          </button>
        </div>
      </form>
    </div>
  )
}

function UrlAnalyzerPage() {
  const navigate = useNavigate()
  const [url, setUrl] = useState('https://bit.ly/verify-paypal-secure-login')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(event) {
    event.preventDefault()
    setLoading(true)
    setError('')

    try {
      const result = await apiRequest('/api/analyze/url', {
        method: 'POST',
        body: JSON.stringify({ url }),
      })
      navigate('/analysis', { state: { analysis: result } })
    } catch (err) {
      setError(err.message || 'Unable to analyze the URL.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.22em] text-cyan-300">Link verification</p>
        <h1 className="mt-2 text-3xl font-bold text-white">URL phishing analyzer</h1>
      </div>

      <form onSubmit={handleSubmit} className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
        <label className="space-y-2">
          <span className="text-sm text-slate-300">Website URL</span>
          <input value={url} onChange={(event) => setUrl(event.target.value)} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-400" />
        </label>

        <div className="mt-4 rounded-xl border border-slate-700 bg-slate-950/80 p-4 text-sm text-slate-300">
          Heuristic detection only — this system does not open the destination URL. It checks hostname structure, suspicious patterns, shortened links, and common phishing signals.
        </div>

        {error && <div className="mt-4 rounded-xl border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}

        <div className="mt-5 flex justify-end">
          <button type="submit" disabled={loading} className="rounded-xl bg-violet-500 px-5 py-3 font-semibold text-white transition hover:bg-violet-400 disabled:cursor-not-allowed disabled:opacity-60">
            {loading ? 'Checking URL...' : 'Analyze URL'}
          </button>
        </div>
      </form>
    </div>
  )
}

function AnalysisPage() {
  const location = useLocation()
  const analysis = location.state?.analysis

  if (!analysis) {
    return (
      <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-8 text-center shadow-glow">
        <ShieldAlert className="mx-auto h-12 w-12 text-amber-300" />
        <h1 className="mt-4 text-2xl font-bold text-white">No analysis available</h1>
        <p className="mt-2 text-slate-400">Submit an email or URL to generate a phishing risk assessment.</p>
        <div className="mt-6 flex justify-center gap-3">
          <Link to="/email" className="rounded-xl bg-cyan-500 px-4 py-2 font-medium text-slate-950">Analyze email</Link>
          <Link to="/url" className="rounded-xl border border-slate-600 px-4 py-2 font-medium text-white">Analyze URL</Link>
        </div>
      </div>
    )
  }

  const riskStyle = getRiskStyle(analysis.risk_level)

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-6 shadow-glow">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.22em] text-cyan-300">Assessment result</p>
            <h1 className="mt-2 text-3xl font-bold text-white">{analysis.analysis_type === 'url' ? 'URL analysis' : 'Email analysis'}</h1>
          </div>
          <div className={`inline-flex items-center rounded-full px-4 py-2 text-sm font-semibold ${riskStyle}`}>
            {analysis.risk_level}
          </div>
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-[0.85fr_1.15fr]">
          <div className="rounded-2xl border border-slate-700 bg-slate-950/80 p-5 text-center">
            <div className={`text-6xl font-black ${getScoreTone(analysis.risk_score)}`}>{analysis.risk_score}</div>
            <div className="mt-2 text-sm uppercase tracking-[0.2em] text-slate-400">Risk score</div>
            <div className="mt-4 flex justify-center">
              <span className={`inline-flex rounded-full px-3 py-1 text-sm font-medium ${riskStyle}`}>{analysis.risk_level}</span>
            </div>
            <div className="mt-4 text-sm text-slate-300">Confidence: {analysis.confidence}</div>
          </div>

          <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/80 p-5">
            <h2 className="text-xl font-semibold text-white">Summary</h2>
            <p className="text-slate-300">{analysis.summary}</p>
            <div className="rounded-xl border border-slate-700 bg-slate-900 p-3 text-sm text-slate-300">
              {analysis.analysis_type === 'url'
                ? `Target: ${analysis.submitted.url}`
                : `Sender: ${analysis.submitted.sender_email || 'Not provided'}`}
            </div>
            <div className="grid gap-2 text-sm text-slate-400 sm:grid-cols-2">
              <div><span className="text-slate-500">Created:</span> {formatDate(analysis.created_at)}</div>
              <div><span className="text-slate-500">Evidence:</span> {analysis.evidence.length} findings</div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="space-y-6">
          <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
            <h2 className="text-xl font-semibold text-white">Detected indicators</h2>
            <div className="mt-4 space-y-4">
              {(analysis.indicators || []).map((indicator) => (
                <div key={indicator.name} className="rounded-xl border border-slate-700 bg-slate-950/80 p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <h3 className="font-medium text-white">{indicator.name}</h3>
                      <p className="mt-1 text-sm text-slate-300">{indicator.explanation}</p>
                    </div>
                    <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${getRiskStyle(indicator.severity === 'High' ? 'High Risk' : indicator.severity === 'Medium' ? 'Medium Risk' : 'Low Risk')}`}>
                      {indicator.severity}
                    </span>
                  </div>
                  <div className="mt-3 text-xs text-slate-400">Evidence: {indicator.evidence.join(', ')}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
            <h2 className="text-xl font-semibold text-white">Evidence</h2>
            <ul className="mt-4 list-disc space-y-2 pl-5 text-slate-300">
              {(analysis.evidence || []).length ? analysis.evidence.map((item) => <li key={item}>{item}</li>) : <li>No specific evidence was extracted in the submitted data.</li>}
            </ul>
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
            <h2 className="text-xl font-semibold text-white">Recommended actions</h2>
            <ul className="mt-4 space-y-3">
              {(analysis.recommendations || []).map((item) => (
                <li key={item} className="flex gap-3 rounded-xl border border-slate-700 bg-slate-950/70 p-3 text-sm text-slate-200">
                  <BadgeCheck className="mt-0.5 h-4 w-4 text-cyan-300" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
            <h2 className="text-xl font-semibold text-white">Limitations</h2>
            <ul className="mt-4 space-y-3 text-sm text-slate-300">
              {(analysis.limitations || []).map((item) => (
                <li key={item} className="flex gap-3 rounded-xl border border-amber-500/30 bg-amber-500/5 p-3">
                  <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-300" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

function ReportsPage() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedId, setSelectedId] = useState(null)
  const [riskFilter, setRiskFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')

  async function loadReports() {
    setLoading(true)
    try {
      const response = await apiRequest('/api/reports')
      setScans(response.scans || [])
      if (response.scans?.[0]) setSelectedId(response.scans[0].id)
    } catch (error) {
      console.error(error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadReports()
  }, [])

  const filteredScans = scans.filter((scan) => {
    const matchesRisk = riskFilter === 'all' || scan.risk_level === riskFilter
    const matchesType = typeFilter === 'all' || scan.analysis_type === typeFilter
    return matchesRisk && matchesType
  })

  const selectedScan = filteredScans.find((scan) => String(scan.id) === String(selectedId)) || filteredScans[0] || null

  async function deleteScan(scanId) {
    try {
      await apiRequest(`/api/reports/${scanId}`, { method: 'DELETE' })
      await loadReports()
    } catch (error) {
      console.error(error)
    }
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(scans, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'phishing-report.json'
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.22em] text-cyan-300">Evidence archive</p>
          <h1 className="mt-2 text-3xl font-bold text-white">Security reports</h1>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={exportJson} className="inline-flex items-center gap-2 rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-200">
            <Download className="h-4 w-4" /> JSON
          </button>
          <a href={`${API_BASE}/api/reports/export?format=csv`} className="inline-flex items-center gap-2 rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-200">
            <Download className="h-4 w-4" /> CSV
          </a>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-4 shadow-glow">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)} className="rounded-xl border border-slate-600 bg-slate-950 px-3 py-2 text-white">
            <option value="all">All risk levels</option>
            <option value="Low Risk">Low Risk</option>
            <option value="Medium Risk">Medium Risk</option>
            <option value="High Risk">High Risk</option>
            <option value="Critical Risk">Critical Risk</option>
          </select>
          <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className="rounded-xl border border-slate-600 bg-slate-950 px-3 py-2 text-white">
            <option value="all">All analyses</option>
            <option value="email">Email</option>
            <option value="url">URL</option>
          </select>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.95fr_1.45fr]">
        <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-4 shadow-glow">
          <h2 className="text-lg font-semibold text-white">Saved scans</h2>
          <div className="mt-3 space-y-2">
            {loading ? <div className="text-slate-400">Loading reports…</div> : filteredScans.length === 0 ? <div className="text-slate-400">No scan records match the current filters.</div> : filteredScans.map((scan) => (
              <button key={scan.id} onClick={() => setSelectedId(scan.id)} className={className('w-full rounded-xl border p-3 text-left transition', selectedScan && selectedScan.id === scan.id ? 'border-cyan-500 bg-cyan-500/10' : 'border-slate-700 bg-slate-950/70 hover:border-slate-500')}>
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-white">#{scan.id} · {scan.analysis_type}</div>
                    <div className="text-xs text-slate-400">{formatDate(scan.created_at)}</div>
                  </div>
                  <span className={`inline-flex rounded-full px-2 py-1 text-[10px] font-medium ${getRiskStyle(scan.risk_level)}`}>{scan.risk_level}</span>
                </div>
                <div className="mt-2 text-sm text-slate-300">Score: {scan.risk_score}</div>
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 shadow-glow">
          {selectedScan ? (
            <>
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-xl font-semibold text-white">Scan #{selectedScan.id}</h2>
                  <div className="text-sm text-slate-400">{selectedScan.analysis_type} · {formatDate(selectedScan.created_at)}</div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`inline-flex rounded-full px-3 py-1 text-sm font-medium ${getRiskStyle(selectedScan.risk_level)}`}>{selectedScan.risk_level}</span>
                  <button onClick={() => deleteScan(selectedScan.id)} className="rounded-xl border border-red-500/30 bg-red-500/10 p-2 text-red-300"><Trash2 className="h-4 w-4" /></button>
                </div>
              </div>

              <div className="mt-5 grid gap-4 md:grid-cols-2">
                <div className="rounded-xl border border-slate-700 bg-slate-950/75 p-4">
                  <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Risk score</div>
                  <div className={`mt-2 text-3xl font-black ${getScoreTone(selectedScan.risk_score)}`}>{selectedScan.risk_score}</div>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-950/75 p-4">
                  <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Summary</div>
                  <div className="mt-2 text-sm text-slate-200">{JSON.parse(selectedScan.raw_result).summary}</div>
                </div>
              </div>

              <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950/75 p-4">
                <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Submitted data</div>
                <pre className="mt-3 overflow-auto text-xs text-slate-300">{JSON.stringify(JSON.parse(selectedScan.raw_result).submitted, null, 2)}</pre>
              </div>
            </>
          ) : (
            <div className="text-slate-300">No record selected.</div>
          )}
        </div>
      </div>
    </div>
  )
}

function Layout() {
  const [open, setOpen] = useState(false)
  const location = useLocation()

  useEffect(() => {
    setOpen(false)
  }, [location.pathname])

  const links = [
    { to: '/', label: 'Dashboard', icon: BarChart3 },
    { to: '/email', label: 'Email Analyzer', icon: Mail },
    { to: '/url', label: 'URL Analyzer', icon: Globe },
    { to: '/reports', label: 'Reports', icon: FileText },
  ]

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex max-w-7xl gap-6 px-4 py-5 md:px-6 xl:px-8">
        <aside className="hidden w-72 shrink-0 rounded-2xl border border-slate-800 bg-slate-900/80 p-4 shadow-glow lg:block">
          <div className="flex items-center gap-3 border-b border-slate-700 pb-4">
            <div className="bg-cyan-500/15 p-2.5 rounded-xl text-cyan-300"><ShieldCheck className="h-5 w-5" /></div>
            <div>
              <div className="font-semibold text-white">PhishGuard</div>
              <div className="text-xs text-slate-400">Intel analysis</div>
            </div>
          </div>

          <nav className="mt-5 space-y-2">
            {links.map(({ to, label, icon: Icon }) => (
              <NavLink key={to} to={to} className={({ isActive }) => className('flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition', isActive ? 'bg-cyan-500/15 text-cyan-100 border border-cyan-500/20' : 'text-slate-300 hover:bg-slate-800')}>
                <Icon className="h-4 w-4" />
                {label}
              </NavLink>
            ))}
          </nav>
        </aside>

        <div className="flex-1">
          <header className="mb-6 rounded-2xl border border-slate-800 bg-slate-900/80 p-4 shadow-glow">
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <button onClick={() => setOpen((value) => !value)} className="rounded-xl border border-slate-700 bg-slate-950 p-2 lg:hidden">
                  <Menu className="h-5 w-5 text-slate-200" />
                </button>
                <div className="flex items-center gap-2 text-sm text-slate-300">
                  <Bell className="h-4 w-4 text-cyan-300" />
                  Threat monitoring active
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-200">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  Heuristic model active
                </div>
              </div>
            </div>

            {open && (
              <nav className="mt-4 space-y-2 lg:hidden">
                {links.map(({ to, label, icon: Icon }) => (
                  <NavLink key={to} to={to} className={({ isActive }) => className('flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium', isActive ? 'bg-cyan-500/15 text-cyan-100' : 'text-slate-300')}>
                    <Icon className="h-4 w-4" />
                    {label}
                  </NavLink>
                ))}
              </nav>
            )}
          </header>

          <main>
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/email" element={<EmailAnalyzerPage />} />
              <Route path="/url" element={<UrlAnalyzerPage />} />
              <Route path="/analysis" element={<AnalysisPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </div>
  )
}

function App() {
  return (
    <BrowserRouter>
      <Layout />
    </BrowserRouter>
  )
}

export default App
