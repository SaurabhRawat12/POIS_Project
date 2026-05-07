import { useState, useEffect } from 'react'
import ExplorerPage from './pages/ExplorerPage'
import PrimalityPage from './pages/PrimalityPage'
import DHPage from './pages/DHPage'
import BirthdayPage from './pages/BirthdayPage'
import MpcPage from './pages/MpcPage'

import { checkHealth } from './api/client'
import './App.css'

const TABS = [
  { id: 'explorer', label: 'Explorer (PA#0)' },
  { id: 'primality', label: 'PA#13 Primality' },
  { id: 'dh', label: 'PA#11 Diffie-Hellman' },
  { id: 'birthday', label: 'PA#9 Birthday' },
  { id: 'mpc', label: 'PA#20 MPC' },
]

export default function App() {
  const [tab, setTab] = useState('explorer')
  const [healthy, setHealthy] = useState(null)

  useEffect(() => {
    let cancelled = false
    checkHealth()
      .then(() => { if (!cancelled) setHealthy(true) })
      .catch(() => { if (!cancelled) setHealthy(false) })
    return () => { cancelled = true }
  }, [])

  return (
    <div className="app-root">
      <header className="app-topbar">
        <div className="app-brand">CS8.401 — Minicrypt Clique Explorer</div>
        <nav className="app-tabs">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`app-tab ${tab === t.id ? 'active' : ''}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>
        <div className={`app-health ${healthy === true ? 'ok' : healthy === false ? 'down' : ''}`}>
          {healthy === true ? '● backend ok' : healthy === false ? '● backend down' : '● checking…'}
        </div>
      </header>

      <main className="app-main">
        {tab === 'explorer' && <ExplorerPage />}
        {tab === 'primality' && <PrimalityPage />}
        {tab === 'dh' && <DHPage />}
        {tab === 'birthday' && <BirthdayPage />}
        {tab === 'mpc' && <MpcPage />}
      </main>
    </div>
  )
}