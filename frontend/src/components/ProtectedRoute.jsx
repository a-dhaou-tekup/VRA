/**
 * ProtectedRoute — redirects to /login if the user is not authenticated.
 * Wrap any route element with this to require login.
 */
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth()
  const location = useLocation()

  if (!isAuthenticated) {
    // Pass the original path so we can redirect back after login
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return children
}
