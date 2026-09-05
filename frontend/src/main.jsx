import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import "./theme.css";
import App from "./App.jsx";
import Overview from "./pages/Overview.jsx";
import Incidents from "./pages/Incidents.jsx";
import IncidentDetail from "./pages/IncidentDetail.jsx";
import Entities from "./pages/Entities.jsx";
import EntityDetail from "./pages/EntityDetail.jsx";
import Agents from "./pages/Agents.jsx";
import AgentDetail from "./pages/AgentDetail.jsx";
import Simulate from "./pages/Simulate.jsx";
import Audit from "./pages/Audit.jsx";
import Replay from "./pages/Replay.jsx";

const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    children: [
      { index: true, element: <Overview /> },
      { path: "incidents", element: <Incidents /> },
      { path: "incidents/:id", element: <IncidentDetail /> },
      { path: "entities", element: <Entities /> },
      { path: "entities/:uid", element: <EntityDetail /> },
      { path: "agents", element: <Agents /> },
      { path: "agents/:id", element: <AgentDetail /> },
      { path: "simulate", element: <Simulate /> },
      { path: "audit", element: <Audit /> },
      { path: "replay", element: <Replay /> },
    ],
  },
]);

createRoot(document.getElementById("root")).render(
  <StrictMode><RouterProvider router={router} /></StrictMode>
);
