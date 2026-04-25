/**
 * Punto di ingresso dell'applicazione React.
 * Monta il componente radice <App> nel div #root dell'index.html.
 * StrictMode attiva i controlli aggiuntivi di React in fase di sviluppo.
 */
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'

// Trova il div #root nel DOM e vi monta l'app React
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
