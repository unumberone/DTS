import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Button,
  Card,
  Col,
  Divider,
  Progress,
  Radio,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tabs,
  Tag,
  Typography,
  Upload,
  message,
} from "antd";
import {
  UploadOutlined,
  PlayCircleOutlined,
  HistoryOutlined,
  DownloadOutlined,
  SafetyCertificateOutlined,
  WarningOutlined,
} from "@ant-design/icons";

import "../css/filescan.css";

const { Title, Text, Paragraph } = Typography;
const { Dragger } = Upload;

const MODEL_OPTIONS = [
  { label: "CNN-LSTM", value: "cnn_lstm" },
  { label: "LSTM", value: "lstm" },
  { label: "Transformer", value: "transformer" }
];

const SCAN_TYPES = [
  { label: "Quick scan", value: "quick" },
  { label: "Deep scan", value: "deep" },
];

async function hashFileSha256(file) {
  try {
    const buf = await file.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", buf);
    const arr = Array.from(new Uint8Array(digest));
    const hex = arr.map((b) => b.toString(16).padStart(2, "0")).join("");
    return hex;
  } catch {
    return "";
  }
}

function toSizeLabel(bytes = 0) {
  const n = Number(bytes) || 0;
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function riskFromConfidence(status, conf) {
  if (status === "benign") return "Safe";
  if (status === "suspicious") {
    if (conf >= 50) return "Medium Risk";
    return "Low Risk";
  }
  // malicious
  if (conf >= 80) return "Critical";
  if (conf >= 60) return "High Risk";
  return "Medium Risk";
}

// mock nhẹ để UI chạy; sau này thay bằng fetch Flask
function mockAnalyze({ scanType, model }) {
  const base = scanType === "deep" ? 0.12 : 0.22;
  const flip = Math.random() < base;
  const status = flip ? "malicious" : "benign";

  const conf =
    status === "malicious"
      ? 88 + Math.random() * 12
      : 85 + Math.random() * 10;

  return {
    status,
    confidence: Number(conf.toFixed(1)),
    modelUsed: model,
    notes:
      status === "malicious"
        ? "Potential ransomware-like behavior detected."
        : "No suspicious pattern detected in current scan.",
    indicators: [
      { key: "entropy", label: "Entropy anomaly", value: status === "malicious" ? "High" : "Normal" },
      { key: "api", label: "Suspicious API calls", value: status === "malicious" ? "Detected" : "None" },
      { key: "packer", label: "Packer/obfuscation", value: status === "malicious" ? "Likely" : "Unlikely" },
    ],
  };
}

export default function FileScan() {
  const navigate = useNavigate();
  const [fileRow, setFileRow] = useState(null);
  const [hashing, setHashing] = useState(false);

  const [scanType, setScanType] = useState("quick");
  const [model, setModel] = useState("cnn_lstm");

  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const uploadProps = {
    multiple: false,
    maxCount: 1,
    beforeUpload: () => false,
    showUploadList: false,
    onChange: async (info) => {
      const f = info.file?.originFileObj || info.file;
      if (!f) return;

      setError("");
      setResult(null);

      const baseRow = {
        key: "file",
        fileName: f.name,
        size: toSizeLabel(f.size),
        type: f.type || "unknown",
        hash: "Calculating...",
        rawFile: f,
      };

      setFileRow(baseRow);
      setHashing(true);

      const sha = await hashFileSha256(f);
      setHashing(false);

      setFileRow((prev) =>
        prev
          ? {
            ...prev,
            hash: sha ? sha.slice(0, 32) : "--",
          }
          : prev
      );
    },
  };

  const columns = useMemo(
    () => [
      {
        title: "File Name",
        dataIndex: "fileName",
        key: "fileName",
        render: (v) => <Text className="cg-mono">{v}</Text>,
      },
      { title: "Size", dataIndex: "size", key: "size", width: 120 },
      {
        title: "MDS Hash",
        dataIndex: "hash",
        key: "hash",
        render: (v) => (
          <Text className="cg-mono" type={v === "--" ? "secondary" : undefined}>
            {v}
          </Text>
        ),
      },
      {
        title: "Type",
        dataIndex: "type",
        key: "type",
        width: 160,
        render: (v) => <Tag className="cg-tag-soft">{v}</Tag>,
      },
    ],
    []
  );

  const handleRun = async () => {
    setError("");

    if (!fileRow?.rawFile) {
      setError("Please upload a file before running analysis.");
      return;
    }

    if (hashing) {
      setError("Hash is still being calculated. Try again in a moment.");
      return;
    }

    setRunning(true);
    try {
      // Send file and selected METHOD to backend
      const formData = new FormData();
      formData.append("file", fileRow.rawFile);
      formData.append("method", model);
      formData.append("mode", scanType);

      const res = await fetch("http://localhost:8000/api/scan", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) throw new Error("Backend analysis failed");

      const json = await res.json();

      // Extract primary result based on requested method logic
      let primaryRes = null;
      let allModelsData = [];
      const results = json.results || {};

      // DEEP SCAN Handling
      if (json.requested?.mode === "deep" && results.deep_static) {
        primaryRes = results.deep_static;
        allModelsData.push({
          model: "Deep Engine",
          result: primaryRes.verdict,
          confidence: primaryRes.risk_score
        });
      }
      // QUICK SCAN Handling - Uses hybrid result with all 3 models in parallel
      else if (json.requested?.mode === "quick" && results.hybrid) {
        primaryRes = results.hybrid;

        // Build comparison table from all 3 model results
        if (results.lstm) allModelsData.push({ model: "ML: LSTM", result: results.lstm.verdict, confidence: results.lstm.risk_score || Math.round((results.lstm.confidence || 0) * 100) });
        if (results.cnn_lstm) allModelsData.push({ model: "ML: CNN-LSTM", result: results.cnn_lstm.verdict, confidence: results.cnn_lstm.risk_score || Math.round((results.cnn_lstm.confidence || 0) * 100) });
        if (results.transformer) allModelsData.push({ model: "ML: Transformer", result: results.transformer.verdict, confidence: results.transformer.risk_score || Math.round((results.transformer.confidence || 0) * 100) });
        if (results.rule_only) allModelsData.push({ model: "Rule-based", result: results.rule_only.verdict, confidence: results.rule_only.risk_score });
      }
      else if (model === "all") {
        // Prefer Hybrid as primary view, fallbacks
        primaryRes = results.hybrid || results.rule_only || results.cnn_lstm;

        // Build comparison table
        if (results.hybrid) allModelsData.push({ model: "Hybrid Analysis", result: results.hybrid.verdict, confidence: results.hybrid.risk_score });
        if (results.rule_only) allModelsData.push({ model: "Rule-based", result: results.rule_only.verdict, confidence: results.rule_only.risk_score });
        if (results.list_only) allModelsData.push({ model: "Reputation List", result: results.list_only.verdict, confidence: results.list_only.risk_score });
        if (results.cnn_lstm) allModelsData.push({ model: "ML: CNN-LSTM", result: results.cnn_lstm.verdict, confidence: results.cnn_lstm.risk_score || (results.cnn_lstm.confidence * 100) });
      } else {
        // Single model mode - try to find result by model name, or fallback to hybrid
        primaryRes = results[model] || results.hybrid || results.rule_only;
        // Add single row for comparison tab
        if (primaryRes) {
          allModelsData.push({
            model: model.toUpperCase().replace("_", " "),
            result: primaryRes.verdict,
            confidence: primaryRes.risk_score || (primaryRes.confidence * 100)
          });
        }
      }

      if (!primaryRes) throw new Error("No result returned for selected method");

      const status = primaryRes.verdict || "UNKNOWN";

      let mappedStatus = "benign";
      let displayType = "Benign";

      if (status === "CLEAN") {
        mappedStatus = "benign";
        displayType = "Safe";
      } else if (status === "SUSPICIOUS") {
        mappedStatus = "suspicious";
        displayType = "Suspicious";
      } else if (status === "MALICIOUS") {
        mappedStatus = "malicious";
        displayType = "Malicious";
      } else {
        mappedStatus = "unknown";
        displayType = "Unknown";
      }

      // Confidence / Risk Score handling
      let riskScore = primaryRes.risk_score || 0;
      if (primaryRes.confidence && !primaryRes.risk_score) {
        riskScore = primaryRes.confidence * 100;
      }

      const risk = riskFromConfidence(mappedStatus, riskScore);

      // Build indicators
      const indicators = [
        { key: "classification", label: "Verdict", value: displayType },
        { key: "source", label: "Source", value: primaryRes.source || "Hybrid Engine" },
        { key: "details", label: "Details", value: primaryRes.details || "Analysis complete" },
        { key: "type", label: "File Type", value: json.file?.file_type || "unknown" },
      ];

      if (json.budgets) {
        indicators.push({ key: "stats", label: "Scan Stats", value: `Files: ${json.budgets.files}, Time: ${json.budgets.time.toFixed(2)}s` });
      }

      // Add evidence from primary result
      if (primaryRes.evidence && Array.isArray(primaryRes.evidence)) {
        primaryRes.evidence.forEach((ev, idx) => {
          // Handle both dict evidence and object evidence
          const reason = ev.reason || ev.desc || JSON.stringify(ev);
          const score = ev.score || ev.weight || 0;
          const path = ev.artifact_path ? `[${ev.artifact_path}] ` : "";
          indicators.push({
            key: `ev_${idx}`,
            label: `Evidence Rule`,
            value: `${path}${reason} (Risk: ${score})`
          });
        });
      }

      setResult({
        status: mappedStatus, // benign/suspicious/malicious for UI coloring
        displayType: displayType,
        confidence: riskScore,
        modelUsed: model,
        notes: primaryRes.details,
        risk,
        indicators,
        allModels: allModelsData,
        riskScore: primaryRes.risk_score || 0,
        verdict: status,
        evidence: primaryRes.evidence || [],
        errors: json.errors || [],
        fileType: json.file?.file_type || "unknown",
      });

      message.success(`Analysis completed using ${model}`);
    } catch (e) {
      console.error(e);
      setError(e?.message || "Analysis failed");
    } finally {
      setRunning(false);
    }
  };

  const handleExport = () => {
    if (!result) return;
    const csvContent = "data:text/csv;charset=utf-8,"
      + "Filename,Result,Confidence,Details,Timestamp\n"
      + `${fileRow?.fileName},${result.displayType},${result.confidence}%,${result.notes},${new Date().toISOString()}`;

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `scan_report_${fileRow?.fileName}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const statusUi = useMemo(() => {
    const s = result?.status;
    if (!s) return null;

    if (s === "malicious") {
      return (
        <div className="cg-result-pill cg-result-pill--bad">
          <WarningOutlined />
          <span>Malicious - {result.displayType}</span>
        </div>
      );
    }
    if (s === "suspicious") {
      return (
        <div className="cg-result-pill cg-result-pill--warn" style={{ background: "linear-gradient(135deg, #fa8c16, #faad14)", color: "#fff" }}>
          <WarningOutlined />
          <span>Suspicious</span>
        </div>
      );
    }
    return (
      <div className="cg-result-pill cg-result-pill--good">
        <SafetyCertificateOutlined />
        <span>Safe - Benign</span>
      </div>
    );
  }, [result]);

  const confidence = result?.confidence ?? 0;

  return (
    <div className="cg-filescan">
      <div className="cg-page-head">
        <Title level={3} className="cg-page-title">
          File Scan
        </Title>
        <Paragraph className="cg-page-sub">
          A perfectly aligned and harmonious layout for cybersecurity dashboard.
        </Paragraph>
      </div>

      {error && (
        <Alert
          type="error"
          showIcon
          className="cg-alert"
          message={error}
        />
      )}

      {/* Upload */}
      <Card
        className="cg-card"
        title="File Upload"
        bordered={false}
      >
        <div className="cg-upload-zone">
          <Dragger {...uploadProps} className="cg-dragger">
            <div className="cg-dragger-inner">
              <Text className="cg-dragger-title">Drag-and-drop zone</Text>
              <Button icon={<UploadOutlined />} type="primary">
                Browse file
              </Button>
            </div>
          </Dragger>
        </div>

        <Divider className="cg-divider" />

        <Table
          size="small"
          columns={columns}
          dataSource={fileRow ? [fileRow] : []}
          pagination={false}
          locale={{ emptyText: "No file selected." }}
          className="cg-table"
        />
      </Card>

      {/* Scan Options */}
      <Card
        className="cg-card"
        title="Scan Options"
        bordered={false}
      >
        <Row gutter={[16, 16]} align="middle">
          <Col xs={24} md={10}>
            <Radio.Group
              options={SCAN_TYPES}
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="cg-radio-vertical"
            />
          </Col>

          <Col xs={24} md={14}>
            <div className="cg-select-block">
              <Text className="cg-label-strong">Select Model</Text>
              <Select
                value={model}
                onChange={setModel}
                options={MODEL_OPTIONS}
                className="cg-select"
              />
            </div>
          </Col>
        </Row>

        <div className="cg-run-wrap">
          <Button
            type="primary"
            size="large"
            block
            icon={<PlayCircleOutlined />}
            loading={running}
            onClick={handleRun}
          >
            Run Analysis
          </Button>
        </div>
      </Card>

      {/* Result */}
      <Card
        className="cg-card"
        title="Result"
        bordered={false}
      >
        {!result && (
          <div className="cg-empty-result">
            <Text type="secondary">
              Upload a file and run analysis to see results.
            </Text>
          </div>
        )}

        {result && (
          <>
            <Row gutter={[18, 18]} align="middle">
              <Col xs={24} md={7}>
                {statusUi}
              </Col>

              <Col xs={24} md={8}>
                <div className="cg-gauge">
                  <Progress
                    type="dashboard"
                    percent={Math.round(confidence)}
                    size={140}
                    strokeWidth={10}
                  />
                  <div className="cg-gauge-caption">
                    <Text className="cg-risk-text">{result.risk}</Text>
                  </div>
                </div>
              </Col>

              <Col xs={24} md={9}>
                <Space direction="vertical" size={6}>
                  <div className="cg-confidence-line">
                    <Title level={4} className="cg-confidence-value">
                      {confidence}% Confidence
                    </Title>
                    <Tag
                      color={result.status === "malicious" ? "red" : result.status === "suspicious" ? "orange" : "green"}
                      className="cg-risk-tag"
                    >
                      {result.risk}
                    </Tag>
                  </div>
                  <Text type="secondary">
                    {result.notes}
                  </Text>

                  <div className="cg-result-meta">
                    <Tag className="cg-tag-soft">
                      Scan: {scanType}
                    </Tag>
                    <Tag className="cg-tag-soft">
                      Model: {result.modelUsed}
                    </Tag>
                  </div>
                </Space>
              </Col>
            </Row>

            <Divider className="cg-divider" />

            <Tabs
              defaultActiveKey="overview"
              items={[
                {
                  key: "overview",
                  label: "Overview",
                  children: (
                    <Row gutter={[16, 16]}>
                      <Col xs={24} md={6}>
                        <Card className="cg-mini" bordered={false}>
                          <Statistic
                            title="Classification"
                            value={result.displayType}
                            valueStyle={{ color: result.status === "malicious" ? "#ff4d4f" : result.status === "suspicious" ? "#faad14" : "#52c41a" }}
                          />
                        </Card>
                      </Col>
                      <Col xs={24} md={6}>
                        <Card className="cg-mini" bordered={false}>
                          <Statistic title="File Type" value={result.isPE ? "PE Executable" : "Document/Other"} />
                        </Card>
                      </Col>
                      <Col xs={24} md={6}>
                        <Card className="cg-mini" bordered={false}>
                          <Statistic title="Risk Level" value={result.risk} />
                        </Card>
                      </Col>
                      <Col xs={24} md={6}>
                        <Card className="cg-mini" bordered={false}>
                          <Statistic title="Suspicious Strings" value={result.suspiciousCount || 0} />
                        </Card>
                      </Col>
                    </Row>
                  ),
                },
                {
                  key: "indicators",
                  label: "Indicators",
                  children: (
                    <div className="cg-indicators">
                      {result.indicators?.map((it) => (
                        <div key={it.key} className="cg-indicator-row">
                          <Text strong>{it.label}</Text>
                          <Tag
                            color={
                              result.status === "malicious" ? "red" : result.status === "suspicious" ? "orange" : "green"
                            }
                          >
                            {it.value}
                          </Tag>
                        </div>
                      ))}
                    </div>
                  ),
                },
                {
                  key: "comparison",
                  label: "Model Comparison",
                  children: (
                    <div className="cg-model-comparison">
                      <Row gutter={[12, 12]}>
                        {result.allModels?.map((m) => (
                          <Col xs={24} md={8} key={m.model}>
                            <Card
                              className="cg-mini"
                              bordered={false}
                              style={{
                                borderLeft: m.result === "Benign" ? "3px solid #52c41a" :
                                  m.result === "Suspicious" ? "3px solid #faad14" : "3px solid #ff4d4f"
                              }}
                            >
                              <Statistic
                                title={m.model}
                                value={m.result}
                                valueStyle={{
                                  color: m.result === "Benign" ? "#52c41a" :
                                    m.result === "Suspicious" ? "#faad14" : "#ff4d4f",
                                  fontSize: "16px"
                                }}
                              />
                              <Text type="secondary">{m.confidence}% confidence</Text>
                            </Card>
                          </Col>
                        ))}
                      </Row>
                      {result.allModels?.length > 0 && (
                        <div style={{ marginTop: 16, padding: 12, background: "#f5f5f5", borderRadius: 8 }}>
                          <Text strong>Analysis Summary: </Text>
                          <Text>
                            {result.allModels.filter(m => m.result === "Benign").length} of 3 models classify as Benign,
                            {result.allModels.filter(m => m.result !== "Benign" && m.result !== "Suspicious").length} as Malicious,
                            {result.allModels.filter(m => m.result === "Suspicious").length} as Suspicious.
                          </Text>
                        </div>
                      )}
                    </div>
                  ),
                },
              ]}
            />

            <div className="cg-result-actions">
              <Button icon={<HistoryOutlined />} onClick={() => navigate("/scan-history")}>
                Lịch sử quét
              </Button>
              <Button onClick={() => navigate("/overview")}>
                Xem Dashboard
              </Button>
              <Button type="primary" icon={<DownloadOutlined />} onClick={handleExport}>
                Export result
              </Button>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
