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
  { data: { id: "scada", label: "SCADA" }, position: { x: 300, y: 180 } },
  { data: { id: "hmi", label: "HMI-01" }, position: { x: 500, y: 180 } },
  { data: { id: "plc1", label: "PLC-01" }, position: { x: 400, y: 320 } },
  { data: { id: "plc2", label: "PLC-02" }, position: { x: 600, y: 320 } },
  { data: { id: "rtu", label: "RTU-01" }, position: { x: 200, y: 320 } },

  { data: { source: "scada", target: "hmi" } },
  { data: { source: "hmi", target: "plc1" } },
  { data: { source: "hmi", target: "plc2" } },
  { data: { source: "rtu", target: "scada" } },
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
                padding: 30,
              }}
              style={{ width: "100%", height: "400px" }}
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
                  <div className={`severity ${alert.severity.toLowerCase()}`}>
                    {alert.severity}
                  </div>

                  <h3>{alert.title}</h3>

                  <p>
                    {alert.source} → {alert.target}
                  </p>
                </div>
              ))}
            </div>
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

          <button>Run Simulation</button>
        </section>
      </main>
    </div>
  );
}

export default App;