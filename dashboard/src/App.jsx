import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetails from './pages/ScanDetails'
import NewScan from './pages/NewScan'
import Targets from './pages/Targets'
import KnowledgeBase from './pages/KnowledgeBase'
import Settings from './pages/Settings'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="scans" element={<Scans />} />
        <Route path="scans/:scanId" element={<ScanDetails />} />
        <Route path="scans/new" element={<NewScan />} />
        <Route path="targets" element={<Targets />} />
        <Route path="knowledge-base" element={<KnowledgeBase />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  )
}

export default App

