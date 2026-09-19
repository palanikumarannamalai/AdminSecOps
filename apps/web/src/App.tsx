import { Link, Route, Routes } from 'react-router';
import { AssessmentLayout } from './app/AssessmentLayout';
import { Layout } from './app/Layout';
import { EmptyState } from './components/States';
import { AboutPage } from './pages/AboutPage';
import { ComparePage } from './pages/ComparePage';
import { ControlsPage } from './pages/ControlsPage';
import { EvidencePage } from './pages/EvidencePage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import { FrameworksPage } from './pages/FrameworksPage';
import { HomePage } from './pages/HomePage';
import { HostedGuidancePage } from './pages/HostedGuidancePage';
import { HostedHomePage } from './pages/HostedHomePage';
import { IS_HOSTED } from './mode';
import { InventoryPage } from './pages/InventoryPage';
import { LibraryPage } from './pages/LibraryPage';
import { OverviewPage } from './pages/OverviewPage';
import { ReportsPage } from './pages/ReportsPage';

function NotFoundPage() {
  return (
    <EmptyState title="Page not found">
      <p>
        <Link to="/">Go to assessments</Link>
      </p>
    </EmptyState>
  );
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={IS_HOSTED ? <HostedHomePage /> : <HomePage />} />
        <Route path="assessments/:assessmentId" element={<AssessmentLayout />}>
          <Route index element={<OverviewPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/:findingId" element={<FindingDetailPage />} />
          <Route path="controls" element={<ControlsPage />} />
          <Route path="evidence" element={<EvidencePage />} />
          <Route path="inventory" element={<InventoryPage />} />
          <Route path="frameworks" element={<FrameworksPage />} />
          <Route path="reports" element={<ReportsPage />} />
        </Route>
        <Route path="compare" element={<ComparePage />} />
        <Route path="library" element={<LibraryPage />} />
        <Route path="about" element={IS_HOSTED ? <HostedGuidancePage /> : <AboutPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
