import React, { useMemo, useState } from "react";
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
  { label: "Auto", value: "auto" },
  { label: "LSTM", value: "lstm" },
  { label: "CNN", value: "cnn" },
  { label: "Transformer", value: "transformer" },
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
  if (status === "benign") return "Low Risk";
  if (conf >= 95) return "High Risk";
  if (conf >= 80) return "Medium Risk";
  return "Low Risk";
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
  const [fileRow, setFileRow] = useState(null);
  const [hashing, setHashing] = useState(false);

  const [scanType, setScanType] = useState("quick");
  const [model, setModel] = useState("auto");

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
      // chỗ này sau thay bằng:
      // const json = await analyzeFile({ file, scanType, model })
      const json = mockAnalyze({ scanType, model });

      const risk = riskFromConfidence(json.status, json.confidence);

      setResult({
        ...json,
        risk,
      });

      message.success("Analysis completed");
    } catch (e) {
      setError(e?.message || "Analysis failed");
    } finally {
      setRunning(false);
    }
  };

  const statusUi = useMemo(() => {
    const s = result?.status;
    if (!s) return null;

    if (s === "malicious") {
      return (
        <div className="cg-result-pill cg-result-pill--bad">
          <WarningOutlined />
          <span>Malicious</span>
        </div>
      );
    }
    return (
      <div className="cg-result-pill cg-result-pill--good">
        <SafetyCertificateOutlined />
        <span>Benign</span>
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
                      color={result.status === "malicious" ? "red" : "green"}
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
                            title="Data Status"
                            value={result.status === "malicious" ? "Malicious" : "Benign"}
                          />
                        </Card>
                      </Col>
                      <Col xs={24} md={6}>
                        <Card className="cg-mini" bordered={false}>
                          <Statistic title="Open Points" value={0} />
                        </Card>
                      </Col>
                      <Col xs={24} md={6}>
                        <Card className="cg-mini" bordered={false}>
                          <Statistic title="Enticated Points" value={result.risk} />
                        </Card>
                      </Col>
                      <Col xs={24} md={6}>
                        <Card className="cg-mini" bordered={false}>
                          <Statistic title="Engaged Posits" value={0} />
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
                              result.status === "malicious" ? "red" : "green"
                            }
                          >
                            {it.value}
                          </Tag>
                        </div>
                      ))}
                    </div>
                  ),
                },
              ]}
            />

            <div className="cg-result-actions">
              <Button icon={<HistoryOutlined />}>
                View in Scan History
              </Button>
              <Button type="primary" icon={<DownloadOutlined />}>
                Export result
              </Button>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
