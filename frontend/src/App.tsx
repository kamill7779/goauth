import { Routes, Route, Navigate } from 'react-router-dom'
import LoginPage from './pages/LoginPage'
import AdminLayout from './pages/Admin/AdminLayout'
import DashboardPage from './pages/Admin/DashboardPage'
import UsersPage from './pages/Admin/UsersPage'
import TenantsPage from './pages/Admin/TenantsPage'
import RolesPage from './pages/Admin/RolesPage'
import OAuthPage from './pages/Admin/OAuthPage'
import SessionsPage from './pages/Admin/SessionsPage'
import AuditPage from './pages/Admin/AuditPage'
import SettingsPage from './pages/Admin/SettingsPage'
import SecurityPage from './pages/Admin/SecurityPage'

function App() {
  return (
    <Routes>
      <Route path="/" element={<LoginPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/admin" element={<AdminLayout><DashboardPage /></AdminLayout>} />
      <Route path="/admin/dashboard" element={<AdminLayout><DashboardPage /></AdminLayout>} />
      <Route path="/admin/users" element={<AdminLayout><UsersPage /></AdminLayout>} />
      <Route path="/admin/tenants" element={<AdminLayout><TenantsPage /></AdminLayout>} />
      <Route path="/admin/roles" element={<AdminLayout><RolesPage /></AdminLayout>} />
      <Route path="/admin/oauth" element={<AdminLayout><OAuthPage /></AdminLayout>} />
      <Route path="/admin/sessions" element={<AdminLayout><SessionsPage /></AdminLayout>} />
      <Route path="/admin/audit" element={<AdminLayout><AuditPage /></AdminLayout>} />
      <Route path="/admin/settings" element={<AdminLayout><SettingsPage /></AdminLayout>} />
      <Route path="/admin/security" element={<AdminLayout><SecurityPage /></AdminLayout>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App
