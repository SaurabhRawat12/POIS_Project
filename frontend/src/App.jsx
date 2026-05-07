import { useState, useEffect } from 'react'
import ExplorerPage from './pages/ExplorerPage'
import PA1Page from './pages/PA1Page'
import PA2Page from './pages/PA2Page'
import PA3Page from './pages/PA3Page'
import PA4Page from './pages/PA4Page'
import PA5Page from './pages/PA5Page'
import PA6Page from './pages/PA6Page'
import PA7Page from './pages/PA7Page'
import PA8Page from './pages/PA8Page'
import BirthdayPage from './pages/BirthdayPage'
import DHPage from './pages/DHPage'
import PrimalityPage from './pages/PrimalityPage'
import { checkHealth } from './api/client'
import './App.css'

const TABS = [
  { id: 'explorer', label: 'Explorer (PA#0)' },
  { id: 'pa1', label: 'PA#1 OWF+PRG' },
  { id: 'pa2', label: 'PA#2 PRF' },
  { id: 'pa3', label: 'PA#3 CPA' },
  { id: 'pa4', label: 'PA#4 Modes' },
  { id: 'pa5', label: 'PA#5 MAC' },
  { id: 'pa6', label: 'PA#6 CCA-Sym' },
  { id: 'pa7', label: 'PA#7 MD Hash' },
  { id: 'pa8', label: 'PA#8 DLP Hash' },
  { id: 'birthday', label: 'PA#9 Birthday' },
  { id: 'dh', label: 'PA#11 DH' },
  { id: 'primality', label: 'PA#13 Primality' },
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
        {tab === 'pa1' && <PA1Page />}
        {tab === 'pa2' && <PA2Page />}
        {tab === 'pa3' && <PA3Page />}
        {tab === 'pa4' && <PA4Page />}
        {tab === 'pa5' && <PA5Page />}
        {tab === 'pa6' && <PA6Page />}
        {tab === 'pa7' && <PA7Page />}
        {tab === 'pa8' && <PA8Page />}
        {tab === 'birthday' && <BirthdayPage />}
        {tab === 'dh' && <DHPage />}
        {tab === 'primality' && <PrimalityPage />}
      </main>
    </div>
  )
}