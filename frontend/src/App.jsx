import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import LoginPage from './features/auth/LoginPage'
import DashboardPage from './features/banking/DashboardPage'
import AccountDetailPage from './features/banking/AccountDetailPage'
import TransfersPage from './features/banking/TransfersPage'
import ProfilePage from './features/banking/ProfilePage'
import AdminConsolePage from './features/admin/AdminConsolePage'
import LabDetailPage from './features/labs/LabDetailPage'
import LabsIndexPage from './features/labs/LabsIndexPage'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<Layout />}>
        <Route path="/banking" element={<DashboardPage />} />
        <Route path="/banking/accounts/:id" element={<AccountDetailPage />} />
        <Route path="/banking/transfers" element={<TransfersPage />} />
        <Route path="/banking/profile" element={<ProfilePage />} />
        <Route path="/admin-console" element={<AdminConsolePage />} />
        <Route path="/lab/:labId" element={<LabDetailPage />} />
        <Route path="/labs" element={<LabsIndexPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/banking" replace />} />
    </Routes>
  )
}
