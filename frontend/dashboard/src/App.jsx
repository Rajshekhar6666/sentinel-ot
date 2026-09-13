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
  anomalyType: "new_write_to_read_only_register",
  anomalyScore: 0.92,
  },
  {
  id: 2,
  severity: "HIGH",
  title: "Unexpected command sequence",
  source: "HMI-01",
  target: "PLC-02",
  anomalyType: "unexpected_command_sequence",
  anomalyScore: 0.85,

  },
  {
    id: 3,
  severity: "MEDIUM",
  title: "Abnormal network traffic",
  source: "RTU-01",
  target: "SCADA",
  anomalyType: "value_outside_historical_range",
  anomalyScore: 0.75,
  },
];

const attackTechniques = [
  {
    name: "Unauthorized Command",
    count: 7,
  },
  {
    name: "Abnormal Communication",
    count: 5,
  },
  {
    name: "Network Discovery",
    count: 3,
  },
  {
    name: "Unexpected Protocol Activity",
    count: 2,
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
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [aiError, setAiError] = useState("");

  const [selectedAsset, setSelectedAsset] = useState("");
  const [simulationResult, setSimulationResult] = useState(null);

  const explainAlert = async (alert) => {
  setSelectedAlert(alert);
  setLoading(true);
  setExplanation(null);
  setAiError("");

  try {
    /*
     * STEP 1:
     * Send the alert to Mansi's backend.
     */
    const backendResponse = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        alert_id: `ALERT-${alert.id}`,
        anomalous_node: alert.source,
        anomaly_type: alert.anomalyType,
        anomaly_score: alert.anomalyScore,
      }),
    });

    if (!backendResponse.ok) {
      throw new Error(
        `Backend request failed: ${backendResponse.status}`
      );
    }

    const backendData = await backendResponse.json();

    /*
     * STEP 2:
     * Give Ollama the original alert + backend's structured analysis.
     *
     * The model is only a narrator.
     * It must not invent security facts.
     */
    const prompt = `
You are a strict OT cybersecurity alert narrator.

Use ONLY the information provided below.

STRICT RULES:
1. Never invent facts.
2. Never invent timestamps, IP addresses, ports, packet counts,
   data volume, protocols, commands, causes, attacker intent,
   malware, compromise, safety impact, or root cause.
3. Do not treat an unusual event as proof of an attack.
4. If something is not supported by the input, return UNKNOWN.
5. Do not invent additional risk or blast-radius information.
6. Treat the BACKEND ANALYSIS as structured evidence.
7. Do not add information outside the ALERT or BACKEND ANALYSIS.
8. Return ONLY valid JSON.
9. Return exactly these keys:
   observed
   possible_meaning
   safe_next_step
10. Do not turn a source/target relationship into a causal statement.
11. Do not turn a classification or label into an observed event.
12. When uncertain, return UNKNOWN.

ALERT:
Title: ${alert.title}
Source: ${alert.source}
Target: ${alert.target}

BACKEND ANALYSIS:
${JSON.stringify(backendData, null, 2)}

CONTENT RULES:
- observed = reproduce only the event explicitly stated in ALERT.
- Do not add verbs, causes, motivations, or interpretations that are not stated.
- possible_meaning = UNKNOWN unless the ALERT or a backend field explicitly
  contains a meaning/explanation statement.
- anomaly_type is a label only. Never infer what physically happened from it.
- attack_techniques are mappings, not proof that the mapped technique occurred.
- blast_radius and risk_score are backend assessment outputs, not proof of
  compromise or operational impact.
- safe_next_step = passive evidence review only.
Return exactly this JSON structure:
{
  "observed": "string",
  "possible_meaning": "string",
  "safe_next_step": "string"
}
`;

    /*
     * STEP 3:
     * Ask Ollama to narrate the structured backend result.
     */
    if (!OLLAMA_URL || !OLLAMA_MODEL) {
      throw new Error("Ollama environment variables are missing");
    }

    const ollamaResponse = await fetch(`${OLLAMA_URL}/api/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        prompt,
        stream: false,
        format: "json",
      }),
    });

    if (!ollamaResponse.ok) {
      throw new Error(
        `Ollama request failed: ${ollamaResponse.status}`
      );
    }

    const ollamaData = await ollamaResponse.json();

    if (!ollamaData.response) {
      throw new Error("Ollama returned no response");
    }

    /*
     * STEP 4:
     * Parse Ollama's JSON safely.
     */
    const rawResponse = ollamaData.response.trim();

    const cleanedResponse = rawResponse
      .replace(/^```json\s*/i, "")
      .replace(/^```\s*/i, "")
      .replace(/```$/i, "")
      .trim();

    let parsedExplanation;

    try {
      parsedExplanation = JSON.parse(cleanedResponse);
    } catch {
      console.error("Raw Ollama response:", rawResponse);
      throw new Error("Ollama returned invalid JSON");
    }

    /*
     * STEP 5:
     * Keep the UI contract predictable.
     */
    setExplanation({
      observed:
        typeof parsedExplanation.observed === "string"
          ? parsedExplanation.observed
          : "UNKNOWN",

      possible_meaning:
        typeof parsedExplanation.possible_meaning === "string"
          ? parsedExplanation.possible_meaning
          : "UNKNOWN",

      safe_next_step:
        typeof parsedExplanation.safe_next_step === "string"
          ? parsedExplanation.safe_next_step
          : "UNKNOWN",
    });
  } catch (error) {
    console.error("AI/backend integration error:", error);

    setAiError(error.message);
    setExplanation(null);
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

    if (!startId) {
      setSimulationResult(null);
      return;
    }

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

  const maxTechniqueCount = Math.max(
    ...attackTechniques.map((technique) => technique.count)
  );

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

        <section className="panel techniques-panel">
          <div className="panel-header">
            <h2>Attack Techniques</h2>
            <span>MOCK DATA</span>
          </div>

          <div className="technique-chart">
            {attackTechniques.map((technique) => {
              const width = `${(technique.count / maxTechniqueCount) * 100}%`;

              return (
                <div className="technique-row" key={technique.name}>
                  <div className="technique-label">
                    <span>{technique.name}</span>
                    <strong>{technique.count}</strong>
                  </div>

                  <div className="technique-bar-track">
                    <div
                      className="technique-bar"
                      style={{ width }}
                    ></div>
                  </div>
                </div>
              );
            })}
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

            {!loading && aiError && (
              <div className="ai-explanation">
                <h3>AI Analysis Error</h3>
                <p>{aiError}</p>
              </div>
            )}

            {!loading && !aiError && explanation && (
              <div className="ai-explanation">
                <h3>
                  AI Analysis
                  {selectedAlert ? ` — ${selectedAlert.title}` : ""}
                </h3>

                <div className="ai-section">
                  <h4>Observed</h4>
                  <p>{explanation.observed}</p>
                </div>

                <div className="ai-section">
                  <h4>Possible Meaning</h4>
                  <p>{explanation.possible_meaning}</p>
                </div>

                <div className="ai-section">
                  <h4>Safe Next Step</h4>
                  <p>{explanation.safe_next_step}</p>
                </div>
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