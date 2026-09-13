import { useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import "./App.css";

const OLLAMA_URL = import.meta.env.VITE_OLLAMA_URL;
const OLLAMA_MODEL = import.meta.env.VITE_OLLAMA_MODEL;

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
    target: "SCADA",
  },
];

const elements = [
  {
    data: {
      id: "scada",
      label: "SCADA",
    },
  },
  {
    data: {
      id: "hmi",
      label: "HMI-01",
    },
  },
  {
    data: {
      id: "plc1",
      label: "PLC-01",
    },
  },
  {
    data: {
      id: "plc2",
      label: "PLC-02",
    },
  },
  {
    data: {
      id: "rtu",
      label: "RTU-01",
    },
  },

  {
    data: {
      source: "scada",
      target: "hmi",
    },
  },
  {
    data: {
      source: "hmi",
      target: "plc1",
    },
  },
  {
    data: {
      source: "hmi",
      target: "plc2",
    },
  },
  {
    data: {
      source: "rtu",
      target: "scada",
    },
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
2. NEVER invent timestamps, IP addresses, ports, packet counts, data volume,
   baseline results, commands, protocol names, causes, attacker intent,
   malware, compromise, data theft, safety impact, or root cause.
3. If information is missing, say UNKNOWN.
4. The word "unusual" does NOT prove malicious activity or compromise.
5. Never recommend shutdown, restart, blocking, isolation, reconfiguration,
   or changing industrial controls.
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
      if (!OLLAMA_URL || !OLLAMA_MODEL) {
        throw new Error("Ollama environment variables are missing");
      }

      const response = await fetch(`${OLLAMA_URL}/api/generate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: OLLAMA_MODEL,
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

    const assetIdMap = {
      "PLC-01": "plc1",
      "PLC-02": "plc2",
      "HMI-01": "hmi",
      SCADA: "scada",
      "RTU-01": "rtu",
    };

    const labelMap = {
      plc1: "PLC-01",
      plc2: "PLC-02",
      hmi: "HMI-01",
      scada: "SCADA",
      rtu: "RTU-01",
    };

    const startId = assetIdMap[selectedAsset];

    // Build an undirected topology graph for compromise-impact analysis.
    const graph = {};

    elements.forEach((element) => {
      const { source, target } = element.data;

      if (!source || !target) {
        return;
      }

      if (!graph[source]) {
        graph[source] = [];
      }

      if (!graph[target]) {
        graph[target] = [];
      }

      graph[source].push(target);
      graph[target].push(source);
    });

    // Breadth-first search calculates distance from the selected asset.
    const distance = new Map();
    const queue = [startId];

    distance.set(startId, 0);

    while (queue.length > 0) {
      const current = queue.shift();

      for (const neighbor of graph[current] || []) {
        if (!distance.has(neighbor)) {
          distance.set(neighbor, distance.get(current) + 1);
          queue.push(neighbor);
        }
      }
    }

    const directImpact = [];
    const potentialImpact = [];

    for (const [id, hop] of distance.entries()) {
      if (id === startId) {
        continue;
      }

      const label = labelMap[id];

      if (!label) {
        continue;
      }

      if (hop === 1) {
        directImpact.push(label);
      } else {
        potentialImpact.push(label);
      }
    }

    // Transparent prototype scoring heuristic.
    const assetCriticality = {
      "PLC-01": 3,
      "PLC-02": 3,
      "HMI-01": 3,
      SCADA: 4,
      "RTU-01": 2,
    };

    const score =
      (assetCriticality[selectedAsset] || 1) +
      directImpact.length * 2 +
      potentialImpact.length;

    let risk = "LOW";

    if (score >= 8) {
      risk = "CRITICAL";
    } else if (score >= 5) {
      risk = "HIGH";
    } else if (score >= 3) {
      risk = "MEDIUM";
    }

    setSimulationResult({
      risk,
      score,
      affected: directImpact,
      potential: potentialImpact,
      path:
        directImpact.length > 0 || potentialImpact.length > 0
          ? `${selectedAsset} → connected topology`
          : `${selectedAsset} has no connected systems`,
    });
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
                  {selectedAlert ? ` — ${selectedAlert.title}` : ""}
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
            Select a compromised OT asset to estimate possible impact and
            affected systems.
          </p>

          <select
            value={selectedAsset}
            onChange={(event) => {
              setSelectedAsset(event.target.value);
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
              <h3>Blast Radius Analysis</h3>

              <p>
                <strong>Compromised Asset:</strong> {selectedAsset}
              </p>

              <p>
                <strong>Risk Level:</strong> {simulationResult.risk}
              </p>

              <p>
                <strong>Risk Score:</strong> {simulationResult.score}
              </p>

              <p>
                <strong>Direct Impact:</strong>{" "}
                {simulationResult.affected.length > 0
                  ? simulationResult.affected.join(", ")
                  : "None"}
              </p>

              <p>
                <strong>Potential Impact:</strong>{" "}
                {simulationResult.potential.length > 0
                  ? simulationResult.potential.join(", ")
                  : "None"}
              </p>

              <p>
                <strong>Topology:</strong> {simulationResult.path}
              </p>

              <p className="simulation-note">
                This is a topology-based prototype assessment. It does not
                confirm compromise or operational impact.
              </p>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;