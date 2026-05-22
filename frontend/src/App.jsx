import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import Login from './pages/Login'
import Overview from './pages/Overview'
import JobsList from './pages/JobsList'
import JobDetail from './pages/JobDetail'
import Metrics from './pages/Metrics'
import Tickets from './pages/Tickets'
import Upload from './pages/Upload'
import Assets from './pages/Assets'
import ManualFindings from './pages/ManualFindings'
import Enrichment from './pages/Enrichment'
import Users from './pages/Users'
import RiskRegister from './pages/RiskRegister'

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public */}
          <Route path="/login" element={<Login />} />

          {/* Protected — requires authentication */}
          <Route
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route path="/" element={<Overview />} />
            <Route path="/jobs" element={<JobsList />} />
            <Route path="/jobs/:id" element={<JobDetail />} />
            <Route path="/metrics" element={<Metrics />} />
            <Route path="/tickets" element={<Tickets />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/findings/new" element={<ManualFindings />} />
            <Route path="/enrichment" element={<Enrichment />} />
            <Route path="/users" element={<Users />} />
            <Route path="/risk-register" element={<RiskRegister />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
