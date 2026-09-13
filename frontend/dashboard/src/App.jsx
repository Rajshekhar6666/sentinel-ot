import { useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import "./App.css";

const alerts = [
  {
    id: 1,
    severity: "CRITICAL",
    title: "Unusual PLC communication detected",
    source: "PLC-01",
    target: "HMI-01",
  },
  {
    id: 2,
    severity: "HIGH",
    title: "Unexpected command sequence",
    source: "HMI-01",
    target: "PLC-02",
  },
  {
    id: 3,
    severity: "MEDIUM",
    title: "Abnormal network traffic",
    source: "RTU-01",
    target: "SCADA-01",
  },
];

const elements = [
  {
    data: { id: "scada", label: "SCADA" },
  },
  {
    data: { id: "hmi", label: "HMI-01" },
  },
  {
    data: { id: "plc1", label: "PLC-01" },
  },
  {
    data: { id: "plc2", label: "PLC-02" },
  },
  {
    data: { id: "rtu", label: "RTU-01" },
  },

  {
    data: { source: "scada", target: "hmi" },
  },
  {
    data: { source: "hmi", target: "plc1" },
  },
  {
    data: { source: "hmi", target: "plc2" },
  },
  {
    data: { source: "rtu", target: "scada" },
  },
];

const stylesheet = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      "background-color": "#2563eb",
      color: "#ffffff",
      "text-valign": "center",
      "text-halign": "center",
      "font-size": "12px",
      width: "55px",
      height: "55px",
    },
  },
  {
    selector: "edge",
    style: {
      width: 2,
      "line-color": "#64748b",
      "target-arrow-color": "#64748b",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
    },
  },
];

function App() {
  const [explanation, setExplanation] = useState("");
  const [loading, setLoading] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedAsset, setSelectedAsset] = useState("");
const [simulationResult, setSimulationResult] = useState(null);

  const explainAlert = async (alert) => {
    setSelectedAlert(alert);
    setLoading(true);
    setExplanation("");

    const prompt = `
You are a strict OT cybersecurity alert narrator.

RULES:
1. Use ONLY facts explicitly present in the ALERT.
2. NEVER invent timestamps, IPs, ports, packet counts, data volume,
   baseline results, commands, protocol names, causes, attacker intent,
   malware, compromise, data theft, safety impact, or root cause.
3. If information is missing, say UNKNOWN.
4. The word "unusual" does NOT prove malicious activity or compromise.
5. Never recommend shutdown, restart, blocking, isolation,
   reconfiguration, or changing industrial controls.
6. Separate observed facts from interpretation.
7. Return exactly these three sections:

OBSERVED:
POSSIBLE MEANING:
SAFE NEXT STEP:

ALERT:
${alert.title}
Source: ${alert.source}
Target: ${alert.target}
`;

    try {
      const response = await fetch("http://localhost:11434/api/generate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "gemma3:4b",
          prompt,
          stream: false,
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama request failed: ${response.status}`);
      }

      const data = await response.json();

      if (!data.response) {
        throw new Error("Ollama returned no response");
      }

      setExplanation(data.response);
    } catch (error) {
      setExplanation(`AI explanation failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };
  const runSimulation = () => {
    if (!selectedAsset) {
      setSimulationResult(null);
      return;
    }

    const impactMap = {
      "PLC-01": {
        risk: "HIGH",
        affected: ["HMI-01"],
        path: "PLC-01 → HMI-01",
      },
      "PLC-02": {
        risk: "HIGH",
        affected: ["HMI-01"],
        path: "PLC-02 → HMI-01",
      },
      "HMI-01": {
        risk: "HIGH",
        affected: ["PLC-01", "PLC-02"],
        path: "HMI-01 → PLC-01 / PLC-02",
      },
      SCADA: {
        risk: "CRITICAL",
        affected: ["HMI-01", "RTU-01"],
        path: "SCADA → HMI-01 / RTU-01",
      },
      "RTU-01": {
        risk: "MEDIUM",
        affected: ["SCADA"],
        path: "RTU-01 → SCADA",
      },
    };

    setSimulationResult(impactMap[selectedAsset]);
  };
  return (
    <div className="dashboard">
      <header className="header">
        <div>
          <h1>SENTINEL-OT</h1>
          <p>Operational Technology Security Dashboard</p>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          SYSTEM ONLINE
        </div>
      </header>

      <main className="main">
        <section className="summary">
          <div className="summary-card">
            <span>Active Alerts</span>
            <strong>3</strong>
          </div>

          <div className="summary-card">
            <span>Critical</span>
            <strong>1</strong>
          </div>

          <div className="summary-card">
            <span>Network Nodes</span>
            <strong>5</strong>
          </div>

          <div className="summary-card">
            <span>Risk Score</span>
            <strong>78/100</strong>
          </div>
        </section>

        <section className="grid">
          <div className="panel graph-panel">
            <div className="panel-header">
              <h2>OT Network Graph</h2>
              <span>LIVE</span>
            </div>

            <CytoscapeComponent
  elements={elements}
  stylesheet={stylesheet}
  layout={{
    name: "grid",
    rows: 2,
    padding: 40,
    fit: false,
  }}
  cy={(cy) => {
    cy.on("layoutstop", () => {
      cy.fit(undefined, 40);
    });
  }}
  style={{
    width: "100%",
    height: "400px",
  }}
/>
          </div>

          <div className="panel alerts-panel">
            <div className="panel-header">
              <h2>Recent Alerts</h2>
              <span>{alerts.length} EVENTS</span>
            </div>

            <div className="alerts">
              {alerts.map((alert) => (
                <div className="alert" key={alert.id}>
                  <div
                    className={`severity ${alert.severity.toLowerCase()}`}
                  >
                    {alert.severity}
                  </div>

                  <h3>{alert.title}</h3>

                  <p>
                    {alert.source} → {alert.target}
                  </p>

                  <button
                    type="button"
                    className="explain-button"
                    onClick={() => explainAlert(alert)}
                    disabled={loading}
                  >
                    {loading && selectedAlert?.id === alert.id
                      ? "Analyzing..."
                      : "Explain with AI"}
                  </button>
                </div>
              ))}
            </div>

            {loading && (
              <div className="ai-explanation">
                <h3>AI Analysis</h3>
                <p>Generating explanation...</p>
              </div>
            )}

            {!loading && explanation && (
              <div className="ai-explanation">
                <h3>
                  AI Analysis
                  {selectedAlert
                    ? ` — ${selectedAlert.title}`
                    : ""}
                </h3>

                <pre>{explanation}</pre>
              </div>
            )}
          </div>
        </section>

        <section className="panel what-if">
  <div className="panel-header">
    <h2>What-If Compromised?</h2>
    <span>SIMULATION</span>
  </div>

  <p>
    Select a compromised OT asset to estimate possible impact and affected systems.
  </p>

  <select
    value={selectedAsset}
    onChange={(e) => {
      setSelectedAsset(e.target.value);
      setSimulationResult(null);
    }}
  >
    <option value="">Select an asset</option>
    <option value="PLC-01">PLC-01</option>
    <option value="PLC-02">PLC-02</option>
    <option value="HMI-01">HMI-01</option>
    <option value="SCADA">SCADA</option>
    <option value="RTU-01">RTU-01</option>
  </select>

  <button
    type="button"
    onClick={runSimulation}
    disabled={!selectedAsset}
  >
    Run Simulation
  </button>

  {simulationResult && (
    <div className="simulation-result">
      <h3>Simulation Result</h3>

      <p>
        <strong>Compromised Asset:</strong> {selectedAsset}
      </p>

      <p>
        <strong>Risk:</strong> {simulationResult.risk}
      </p>

      <p>
        <strong>Affected Systems:</strong>{" "}
        {simulationResult.affected.join(", ")}
      </p>

      <p>
        <strong>Network Path:</strong> {simulationResult.path}
      </p>
    </div>
  )}
</section>
      </main>
    </div>
  );
}

export default App;