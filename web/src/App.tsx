import { BrowserRouter, Routes, Route } from "react-router-dom";
import AppShell from "./components/AppShell";
import Overview from "./pages/Overview";
import Stub from "./pages/Stub";
import Runs from "./pages/Runs";
import RunDetail from "./pages/RunDetail";
import Compare from "./pages/Compare";
import Models from "./pages/Models";
import ModelDetail from "./pages/ModelDetail";
import Onboarding from "./pages/Onboarding";
import Policies from "./pages/Policies";
import Admin from "./pages/Admin";
import Catalog from "./pages/Catalog";

export default function App() {
  return (
    <BrowserRouter basename="/app">
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<Overview />} />
          <Route path="models" element={<Models />} />
          <Route path="models/:sha" element={<ModelDetail />} />
          <Route path="onboarding" element={<Onboarding />} />
          <Route path="runs" element={<Runs />} />
          <Route path="runs/:id" element={<RunDetail />} />
          <Route path="compare" element={<Compare />} />
          <Route path="findings" element={<Stub title="Находки" phase="Ф2" />} />
          <Route path="policies" element={<Policies />} />
          <Route path="catalog" element={<Catalog />} />
          <Route path="gate" element={<Stub title="Гейт и интеграции" phase="Ф6" />} />
          <Route path="admin" element={<Admin />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
