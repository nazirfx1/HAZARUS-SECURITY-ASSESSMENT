import React, { useState, useEffect } from 'react'
import { Shield, FileText, Activity, Settings, Home, Play } from 'lucide-react'

function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [stats, setStats] = useState({
    totalAssessments: 0,
    activeAssessments: 0,
    completedAssessments: 0,
    totalFindings: 0
  })

  useEffect(() => {
    fetchStats()
  }, [])

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/dashboard/stats')
      const data = await response.json()
      setStats(data)
    } catch (error) {
      console.error('Failed to fetch stats:', error)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900">
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-blue-500" />
            <h1 className="text-2xl font-bold text-white">HAZARUS</h1>
          </div>
          <nav className="flex gap-4">
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
                <div className="text-3xl font-bold text-white">{stats.totalAssessments}</div>
              </div>
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
                <div className="text-slate-400 text-sm mb-2">Active</div>
                <div className="text-3xl font-bold text-green-500">{stats.activeAssessments}</div>
              </div>
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
                <div className="text-slate-400 text-sm mb-2">Completed</div>
                <div className="text-3xl font-bold text-blue-500">{stats.completedAssessments}</div>
              </div>
              <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
                <div className="text-slate-400 text-sm mb-2">Total Findings</div>
                <div className="text-3xl font-bold text-orange-500">{stats.totalFindings}</div>
              </div>
            </div>

            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
              <h3 className="text-xl font-bold text-white mb-4">Recent Activity</h3>
              <div className="text-slate-400">No recent activity</div>
            </div>
          </div>
        )}

        {activeTab === 'assessments' && (
          <div>
            <h2 className="text-3xl font-bold text-white mb-6">Assessments</h2>
            <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
              <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded mb-4 flex items-center gap-2">
                <Play className="w-4 h-4" />
                New Assessment
              </button>
              <div className="text-slate-400">No assessments found</div>
            </div>
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
