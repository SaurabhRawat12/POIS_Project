import { useState, useEffect } from 'react'
import ExplorerPage from './pages/ExplorerPage'
import PrimalityPage from './pages/PrimalityPage'
import DHPage from './pages/DHPage'
import BirthdayPage from './pages/BirthdayPage'
import MpcPage from './pages/MpcPage'
import HastadPage from './pages/HastadPage'
import Pa15ForgeryPage from './pages/Pa15_ForgeryPage';
import Pa12DeterminismPage from './pages/Pa12_DeterminismPage';
import Pa16MalleabilityPage from './pages/Pa16_MalleabilityPage';
import Pa17CcaPkcPage from './pages/Pa17_CcaPkcPage';
import Pa18OTPage from './pages/Pa18_OTPage';
import Pa19SecureGatesPage from './pages/Pa19_SecureGatesPage';
import Pa10HmacPage from './pages/Pa10_HmacPage';
import Pa1OwfPrgPage from './pages/Pa1_OwfPrgPage';
import Pa2PrfPage from './pages/Pa2_PrfPage';
import Pa3CpaPage from './pages/Pa3_CpaPage';
import Pa4ModesPage from './pages/Pa4_ModesPage';
import Pa5MacPage from './pages/Pa5_MacPage';
import Pa7MdHashPage from './pages/Pa7_MdHashPage';

import { checkHealth } from './api/client'
import './App.css'

const TABS = [
  { id: 'explorer', label: 'Explorer (PA#0)' },
  { id: 'primality', label: 'PA#13 Primality' },
  { id: 'dh', label: 'PA#11 Diffie-Hellman' },
  { id: 'birthday', label: 'PA#9 Birthday' },
  { id: 'mpc', label: 'PA#20 MPC' },
  { id: 'hastad', label: 'PA#14 Hastad' },
  { id: 'pa15', label: 'PA#15 Forgery' },
  { id: 'pa12', label: 'PA#12 RSA Determinism' },
  { id: 'pa16', label: 'PA#16 ElGamal Malleability' },
  { id: 'pa17', label: 'PA#17 CCA-Secure PKC' },
  { id: 'pa18', label: 'PA#18 Oblivious Transfer' },
  { id: 'pa19', label: 'PA#19 Secure Gates' },
  { id: 'pa10', label: 'PA#10 HMAC' },
  { id: 'pa1', label: 'PA#1 OWF & PRG' },
  { id: 'pa2', label: 'PA#2 PRF (GGM)' },
  { id: 'pa3', label: 'PA#3 CPA' },
  { id: 'pa4', label: 'PA#4 Modes' },
  { id: 'pa5', label: 'PA#5 MAC' },
  { id: 'pa7', label: 'PA#7 MD Hash' },
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
        {tab === 'hastad' && <HastadPage />}
        {tab === 'pa15' && <Pa15ForgeryPage />}
        {tab === 'pa12' && <Pa12DeterminismPage />}
        {tab === 'pa16' && <Pa16MalleabilityPage />}
        {tab === 'pa17' && <Pa17CcaPkcPage />}
        {tab === 'pa18' && <Pa18OTPage />}
        {tab === 'pa19' && <Pa19SecureGatesPage />}
        {tab === 'pa10' && <Pa10HmacPage />}
        {tab === 'pa1' && <Pa1OwfPrgPage />}
        {tab === 'pa2' && <Pa2PrfPage />}
        {tab === 'pa3' && <Pa3CpaPage />}
        {tab === 'pa4' && <Pa4ModesPage />}
        {tab === 'pa5' && <Pa5MacPage />}
        {tab === 'pa7' && <Pa7MdHashPage />}
      </main>
    </div>
  )
}