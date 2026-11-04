import React, { useState, useEffect } from 'react'
import { Shield, FileText, Activity, Settings, Home, Play, AlertTriangle, Clock, CheckCircle, XCircle } from 'lucide-react'

function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [stats, setStats] = useState({
    totalAssessments: 0,
    activeAssessments: 0,
    completedAssessments: 0,
    totalFindings: 0
  })
  const [assessments, setAssessments] = useState([])
  const [recentActivity, setRecentActivity] = useState({ recent_assessments: [], recent_findings: [] })
  const [selectedAssessment, setSelectedAssessment] = useState(null)
  const [findings, setFindings] = useState([])
  const [showNewAssessmentForm, setShowNewAssessmentForm] = useState(false)
  const [newAssessment, setNewAssessment] = useState({ target: '', assessment_id: '' })
  const [authToken, setAuthToken] = useState(localStorage.getItem('hazarus_token') || '')
  const [showLogin, setShowLogin] = useState(!authToken)
  const [loginForm, setLoginForm] = useState({ username: '', password: '' })

  useEffect(() => {
    if (authToken) {
      fetchStats()
      fetchAssessments()
      fetchRecentActivity()
    }
  }, [authToken])

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:8000/dashboard/stats', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
      if (response.ok) {
        const data = await response.json()
        setStats(data)
      }
    } catch (error) {
      console.error('Failed to fetch stats:', error)
    }
  }

  const fetchAssessments = async () => {
    try {
      const response = await fetch('http://localhost:8000/assessments', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
      if (response.ok) {
        const data = await response.json()
        setAssessments(data.assessments)
      }
    } catch (error) {
      console.error('Failed to fetch assessments:', error)
    }
  }

  const fetchRecentActivity = async () => {
    try {
      const response = await fetch('http://localhost:8000/dashboard/recent-activity', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
      if (response.ok) {
        const data = await response.json()
        setRecentActivity(data)
      }
    } catch (error) {
      console.error('Failed to fetch recent activity:', error)
    }
  }

  const fetchFindings = async (assessmentId) => {
    try {
      const response = await fetch(`http://localhost:8000/assessments/${assessmentId}/findings`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
      if (response.ok) {
        const data = await response.json()
        setFindings(data.findings)
      }
    } catch (error) {
      console.error('Failed to fetch findings:', error)
    }
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    try {
      const response = await fetch('http://localhost:8000/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginForm)
      })
      if (response.ok) {
        const data = await response.json()
        setAuthToken(data.access_token)
        localStorage.setItem('hazarus_token', data.access_token)
        setShowLogin(false)
      } else {
        alert('Login failed')
      }
    } catch (error) {
      console.error('Login error:', error)
      alert('Login error')
    }
  }

  const handleCreateAssessment = async (e) => {
    e.preventDefault()
    try {
      const response = await fetch('http://localhost:8000/assessments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({
          assessment_id: newAssessment.assessment_id || `assessment-${Date.now()}`,
          target: newAssessment.target,
          status: 'running',
          start_time: new Date().toISOString(),
          findings_count: 0
        })
      })
      if (response.ok) {
        setShowNewAssessmentForm(false)
        setNewAssessment({ target: '', assessment_id: '' })
        fetchAssessments()
        fetchStats()
      } else {
        alert('Failed to create assessment')
      }
    } catch (error) {
      console.error('Create assessment error:', error)
      alert('Create assessment error')
    }
  }

  const handleDeleteAssessment = async (assessmentId) => {
    if (!confirm('Are you sure you want to delete this assessment?')) return
    try {
      const response = await fetch(`http://localhost:8000/assessments/${assessmentId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
      if (response.ok) {
        fetchAssessments()
        fetchStats()
      }
    } catch (error) {
      console.error('Delete assessment error:', error)
    }
  }

  const handleLogout = async () => {
    try {
      await fetch('http://localhost:8000/auth/logout', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
    } catch (error) {
      console.error('Logout error:', error)
    }
    setAuthToken('')
    localStorage.removeItem('hazarus_token')
    setShowLogin(true)
  }

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-500/10'
      case 'high': return 'text-orange-500 bg-orange-500/10'
      case 'medium': return 'text-yellow-500 bg-yellow-500/10'
      case 'low': return 'text-blue-500 bg-blue-500/10'
      default: return 'text-gray-500 bg-gray-500/10'
    }
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'running': return <Clock className="w-4 h-4 text-yellow-500" />
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-500" />
      case 'failed': return <XCircle className="w-4 h-4 text-red-500" />
      default: return <Activity className="w-4 h-4 text-gray-500" />
    }
  }

  if (showLogin) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="bg-slate-800 p-8 rounded-lg border border-slate-700 w-full max-w-md">
          <div className="flex items-center gap-2 mb-6">
            <Shield className="w-8 h-8 text-blue-500" />
            <h1 className="text-2xl font-bold text-white">HAZARUS</h1>
          </div>
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-slate-400 text-sm mb-2">Username</label>
              <input
                type="text"
                value={loginForm.username}
                onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })}
                className="w-full bg-slate-700 text-white px-4 py-2 rounded border border-slate-600 focus:border-blue-500 focus:outline-none"
                required
              />
            </div>
            <div>
              <label className="block text-slate-400 text-sm mb-2">Password</label>
              <input
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                className="w-full bg-slate-700 text-white px-4 py-2 rounded border border-slate-600 focus:border-blue-500 focus:outline-none"
                required
              />
            </div>
            <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 rounded">
              Login
            </button>
          </form>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-900">
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-blue-500" />
            <h1 className="text-2xl font-bold text-white">HAZARUS</h1>
          </div>
          <nav className="flex gap-4 items-center">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-4 py-2 rounded ${activeTab === 'dashboard' ? 'bg-blue-600 text-white' : 'text-slate-300 hover:text-white'}`}
            >
              <Home className="w-4 h-4 inline mr-2" />
              Dashboard
            </button>
            <button
              onClick={() => setActiveTab('assessments')}
              className={`px-4 py-2 rounded ${activeTab === 'assessments' ? 'bg-blue-600 text-white' : 'text-slate-300 hover:text-white'}`}
            >
              <FileText className="w-4 h-4 inline mr-2" />
              Assessments
            </button>
            <button
              onClick={() => setActiveTab('scope')}
              className={`px-4 py-2 rounded ${activeTab === 'scope' ? 'bg-blue-600 text-white' : 'text-slate-300 hover:text-white'}`}
            >
              <Settings className="w-4 h-4 inline mr-2" />
              Scope
            </button>
            <button
              onClick={handleLogout}
              className="px-4 py-2 rounded text-slate-300 hover:text-white ml-4"
            >
              Logout
            </button>
          </nav>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
        {activeTab === 'dashboard' && (
          <div>
            <h2 className="text-3xl font-bold text-white mb-6">Dashboard</h2>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
                <div className="text-slate-400 text-sm mb-2">Total Assessments</div>
                <div className="text-3xl font-bold text-white">{stats.total_assessments}</div>
              </div>
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
                <div className="text-slate-400 text-sm mb-2">Active</div>
                <div className="text-3xl font-bold text-green-500">{stats.active_assessments}</div>
              </div>
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
                <div className="text-slate-400 text-sm mb-2">Completed</div>
                <div className="text-3xl font-bold text-blue-500">{stats.completed_assessments}</div>
              </div>
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
                <div className="text-slate-400 text-sm mb-2">Total Findings</div>
                <div className="text-3xl font-bold text-orange-500">{stats.total_findings}</div>
              </div>
            </div>

            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
              <h3 className="text-xl font-bold text-white mb-4">Recent Assessments</h3>
              {recentActivity.recent_assessments.length > 0 ? (
                <div className="space-y-3">
                  {recentActivity.recent_assessments.map((assessment) => (
                    <div key={assessment.assessment_id} className="flex items-center justify-between p-3 bg-slate-700/50 rounded">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(assessment.status)}
                        <div>
                          <div className="text-white font-medium">{assessment.target}</div>
                          <div className="text-slate-400 text-sm">{assessment.assessment_id}</div>
                        </div>
                      </div>
                      <div className="text-slate-400 text-sm">
                        {new Date(assessment.created_at).toLocaleDateString()}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-slate-400">No recent assessments</div>
              )}
            </div>

            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
              <h3 className="text-xl font-bold text-white mb-4">Recent Findings</h3>
              {recentActivity.recent_findings.length > 0 ? (
                <div className="space-y-3">
                  {recentActivity.recent_findings.map((finding) => (
                    <div key={finding.id} className="flex items-center justify-between p-3 bg-slate-700/50 rounded">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="w-4 h-4 text-orange-500" />
                        <div>
                          <div className="text-white font-medium">{finding.title}</div>
                          <div className="text-slate-400 text-sm">{finding.assessment_id}</div>
                        </div>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-slate-400">No recent findings</div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'assessments' && (
          <div>
            <h2 className="text-3xl font-bold text-white mb-6">Assessments</h2>
            
            {showNewAssessmentForm ? (
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
                <h3 className="text-xl font-bold text-white mb-4">Create New Assessment</h3>
                <form onSubmit={handleCreateAssessment} className="space-y-4">
                  <div>
                    <label className="block text-slate-400 text-sm mb-2">Target (domain or IP)</label>
                    <input
                      type="text"
                      value={newAssessment.target}
                      onChange={(e) => setNewAssessment({ ...newAssessment, target: e.target.value })}
                      className="w-full bg-slate-700 text-white px-4 py-2 rounded border border-slate-600 focus:border-blue-500 focus:outline-none"
                      placeholder="example.com or 192.168.1.1"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 text-sm mb-2">Assessment ID (optional)</label>
                    <input
                      type="text"
                      value={newAssessment.assessment_id}
                      onChange={(e) => setNewAssessment({ ...newAssessment, assessment_id: e.target.value })}
                      className="w-full bg-slate-700 text-white px-4 py-2 rounded border border-slate-600 focus:border-blue-500 focus:outline-none"
                      placeholder="Auto-generated if empty"
                    />
                  </div>
                  <div className="flex gap-3">
                    <button type="submit" className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded flex items-center gap-2">
                      <Play className="w-4 h-4" />
                      Create Assessment
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowNewAssessmentForm(false)}
                      className="bg-slate-600 hover:bg-slate-700 text-white px-4 py-2 rounded"
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </div>
            ) : (
              <button
                onClick={() => setShowNewAssessmentForm(true)}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded mb-6 flex items-center gap-2"
              >
                <Play className="w-4 h-4" />
                New Assessment
              </button>
            )}

            {selectedAssessment ? (
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-bold text-white">Assessment Details</h3>
                  <button
                    onClick={() => setSelectedAssessment(null)}
                    className="text-slate-400 hover:text-white"
                  >
                    Back to List
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div>
                    <div className="text-slate-400 text-sm">Target</div>
                    <div className="text-white">{selectedAssessment.target}</div>
                  </div>
                  <div>
                    <div className="text-slate-400 text-sm">Status</div>
                    <div className="text-white flex items-center gap-2">
                      {getStatusIcon(selectedAssessment.status)}
                      {selectedAssessment.status}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400 text-sm">Findings</div>
                    <div className="text-white">{selectedAssessment.findings_count}</div>
                  </div>
                  <div>
                    <div className="text-slate-400 text-sm">Created</div>
                    <div className="text-white">{new Date(selectedAssessment.created_at).toLocaleString()}</div>
                  </div>
                </div>

                <h4 className="text-lg font-bold text-white mb-4">Findings</h4>
                {findings.length > 0 ? (
                  <div className="space-y-3">
                    {findings.map((finding) => (
                      <div key={finding.id} className="p-4 bg-slate-700/50 rounded border border-slate-600">
                        <div className="flex items-center justify-between mb-2">
                          <h5 className="text-white font-medium">{finding.title}</h5>
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                            {finding.severity}
                          </span>
                        </div>
                        <p className="text-slate-400 text-sm mb-2">{finding.description}</p>
                        {finding.location && (
                          <div className="text-slate-500 text-sm">Location: {finding.location}</div>
                        )}
                        {finding.remediation && (
                          <div className="text-slate-400 text-sm mt-2">
                            <strong>Remediation:</strong> {finding.remediation}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-slate-400">No findings for this assessment</div>
                )}
              </div>
            ) : (
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
                {assessments.length > 0 ? (
                  <div className="space-y-3">
                    {assessments.map((assessment) => (
                      <div key={assessment.assessment_id} className="flex items-center justify-between p-4 bg-slate-700/50 rounded border border-slate-600">
                        <div className="flex items-center gap-4">
                          {getStatusIcon(assessment.status)}
                          <div>
                            <div className="text-white font-medium">{assessment.target}</div>
                            <div className="text-slate-400 text-sm">{assessment.assessment_id}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          <div className="text-slate-400 text-sm">
                            {assessment.findings_count} findings
                          </div>
                          <button
                            onClick={() => {
                              setSelectedAssessment(assessment)
                              fetchFindings(assessment.assessment_id)
                            }}
                            className="text-blue-400 hover:text-blue-300 text-sm"
                          >
                            View Details
                          </button>
                          <button
                            onClick={() => handleDeleteAssessment(assessment.assessment_id)}
                            className="text-red-400 hover:text-red-300 text-sm"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-slate-400">No assessments found. Create one to get started.</div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === 'scope' && (
          <div>
            <h2 className="text-3xl font-bold text-white mb-6">Scope Configuration</h2>
            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
              <div className="text-slate-400">Scope configuration loaded from config/scope.yaml</div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

export default App
