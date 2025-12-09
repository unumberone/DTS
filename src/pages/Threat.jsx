import React, { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Empty,
  Progress,
  Row,
  Skeleton,
  Space,
  Tag,
  Timeline,
  Typography,
} from "antd";
import {
  DownloadOutlined,
  PlusOutlined,
  EyeOutlined,
  WarningFilled,
  SafetyCertificateOutlined,
  FileTextOutlined,
} from "@ant-design/icons";
import { useNavigate, useParams } from "react-router-dom";
import { getThreatDetail } from "../api/threatApi";

const { Title, Text } = Typography;

const numberFmt = new Intl.NumberFormat();

const normalizeResult = (v) =>
  String(v || "").trim().toLowerCase() === "malicious"
    ? "malicious"
    : "benign";

const normalizePct = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0;
  const pct = n <= 1 ? n * 100 : n;
  return Math.max(0, Math.min(100, Math.round(pct)));
};

const riskTone = (level = "") => {
  const v = String(level).toLowerCase();
  if (v.includes("critical")) return "red";
  if (v.includes("high")) return "volcano";
  if (v.includes("medium")) return "gold";
  return "green";
};

const riskPercent = (level = "") => {
  const v = String(level).toLowerCase();
  if (v.includes("critical")) return 95;
  if (v.includes("high")) return 80;
  if (v.includes("medium")) return 55;
  return 25;
};

export default function Threat() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [data, setData] = useState({
    header: null,
    fileMeta: null,
    detection: null,
    behaviorTimeline: [],
    attackChain: [],
  });

  useEffect(() => {
    if (!id) {
      setLoading(false);
      setError("Missing threat id.");
      return;
    }

    const ac = new AbortController();
    setLoading(true);
    setError("");

    getThreatDetail(id, { signal: ac.signal })
      .then((json) => {
        setData({
          header: json?.header ?? null,
          fileMeta: json?.fileMeta ?? null,
          detection: json?.detection ?? null,
          behaviorTimeline: Array.isArray(json?.behaviorTimeline)
            ? json.behaviorTimeline
            : [],
          attackChain: Array.isArray(json?.attackChain) ? json.attackChain : [],
        });
      })
      .catch((e) => {
        if (e?.name !== "AbortError") setError(e?.message || "Load failed");
      })
      .finally(() => setLoading(false));

    return () => ac.abort();
  }, [id]);

  const header = data.header || {};
  const fileMeta = data.fileMeta || {};
  const detection = data.detection || {};

  const result = normalizeResult(header?.result);
  const confidencePct = normalizePct(header?.confidencePct ?? detection?.modelConfidenceMalicious);
  const riskLevel = header?.riskLevel || detection?.riskLevel || "Unknown";

  const fileName = header?.fileName ?? fileMeta?.fileName ?? "--";
  const sha256 = header?.sha256 ?? fileMeta?.sha256 ?? "--";

  const timelineItems = useMemo(() => {
    return data.behaviorTimeline.map((t, i) => ({
      key: t?.id ?? i,
      color: t?.severity === "high" ? "red" : t?.severity === "medium" ? "orange" : "blue",
      dot:
        t?.severity === "high" ? (
          <WarningFilled />
        ) : (
          <SafetyCertificateOutlined />
        ),
      children: (
        <Space direction="vertical" size={2}>
          <Text strong>{t?.time ?? "--"}</Text>
          <Text type="secondary">{t?.message ?? ""}</Text>
        </Space>
      ),
    }));
  }, [data.behaviorTimeline]);

  const attackNodes = useMemo(() => {
    // Expect array like:
    // [{ key, label, subLabel, tone, toKey }]
    // We'll render a simple chain layout.
    return data.attackChain.map((n, i) => ({
      key: n?.key ?? i,
      label: n?.label ?? "Step",
      subLabel: n?.subLabel ?? "",
      tone: n?.tone ?? "default",
    }));
  }, [data.attackChain]);

  const handleViewFullScan = () => {
    const to = header?.fullScanPath || detection?.fullScanPath || "/file-scan";
    navigate(to);
  };

  const handleExport = () => {
    // Hook later with backend export endpoint
    // e.g. window.open(`${API_BASE}/api/threats/${id}/report`)
    console.log("export threat report", id);
  };

  const handleAddIncident = () => {
    // Hook later
    console.log("add to incident", id);
  };

  return (
    <div style={{ width: "100%" }}>
      <Row justify="space-between" align="middle" gutter={[12, 12]}>
        <Col>
          <Space direction="vertical" size={2}>
            <Title level={4} style={{ margin: 0 }}>
              Threat Details
            </Title>
            <Space size={8} wrap>
              <Text strong>{fileName}</Text>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {sha256}
              </Text>
            </Space>
          </Space>
        </Col>

        <Col>
          <Space wrap>
            <Button icon={<DownloadOutlined />} onClick={handleExport}>
              Export Threat Report
            </Button>
            <Button icon={<PlusOutlined />} onClick={handleAddIncident}>
              Add to Incident
            </Button>
            <Button type="primary" icon={<EyeOutlined />} onClick={handleViewFullScan}>
              View Full Scan Details
            </Button>
          </Space>
        </Col>
      </Row>

      <Divider style={{ margin: "12px 0 16px" }} />

      {error && (
        <Alert
          type="error"
          showIcon
          message="Failed to load threat detail"
          description={error}
          style={{ marginBottom: 12 }}
        />
      )}

      {/* TOP STATUS STRIP */}
      <Card style={{ marginBottom: 12 }}>
        {loading ? (
          <Skeleton active paragraph={{ rows: 1 }} />
        ) : (
          <Row gutter={[16, 16]} align="middle">
            <Col xs={24} md={8}>
              <Space align="center">
                <span
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: 10,
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    background: result === "malicious" ? "#fff1f0" : "#f6ffed",
                    border: "1px solid",
                    borderColor: result === "malicious" ? "#ffccc7" : "#b7eb8f",
                  }}
                >
                  <WarningFilled style={{ color: result === "malicious" ? "#cf1322" : "#389e0d" }} />
                </span>
                <Space direction="vertical" size={0}>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    Status
                  </Text>
                  <Tag color={result === "malicious" ? "red" : "green"} style={{ marginInlineEnd: 0 }}>
                    {result === "malicious" ? "MALICIOUS (Ransomware)" : "BENIGN"}
                  </Tag>
                </Space>
              </Space>
            </Col>

            <Col xs={24} md={8}>
              <Space direction="vertical" size={2} style={{ width: "100%" }}>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  Confidence
                </Text>
                <Progress
                  percent={confidencePct}
                  status={result === "malicious" ? "exception" : "normal"}
                  showInfo
                />
              </Space>
            </Col>

            <Col xs={24} md={8}>
              <Row align="middle" gutter={[12, 12]}>
                <Col flex="auto">
                  <Space direction="vertical" size={2}>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      Critical Risk Level
                    </Text>
                    <Badge
                      color={riskTone(riskLevel)}
                      text={<Text strong>{String(riskLevel)}</Text>}
                    />
                  </Space>
                </Col>
                <Col>
                  <Progress
                    type="dashboard"
                    percent={riskPercent(riskLevel)}
                    size={80}
                    strokeColor={
                      riskTone(riskLevel) === "red"
                        ? "#ff4d4f"
                        : riskTone(riskLevel) === "volcano"
                        ? "#fa541c"
                        : riskTone(riskLevel) === "gold"
                        ? "#faad14"
                        : "#52c41a"
                    }
                  />
                </Col>
              </Row>
            </Col>
          </Row>
        )}
      </Card>

      <Row gutter={[12, 12]}>
        {/* FILE METADATA */}
        <Col xs={24} lg={14}>
          <Card
            title={
              <Space>
                <FileTextOutlined />
                <span>File Metadata</span>
              </Space>
            }
          >
            {loading ? (
              <Skeleton active paragraph={{ rows: 3 }} />
            ) : (
              <Descriptions
                bordered
                size="small"
                column={{ xs: 1, sm: 2, md: 3 }}
              >
                <Descriptions.Item label="File Name">
                  {fileMeta?.fileName ?? header?.fileName ?? "--"}
                </Descriptions.Item>
                <Descriptions.Item label="File Size">
                  {fileMeta?.fileSizeMb != null
                    ? `${fileMeta.fileSizeMb} MB`
                    : fileMeta?.fileSizeLabel ?? "--"}
                </Descriptions.Item>
                <Descriptions.Item label="File Type">
                  {fileMeta?.fileType ?? "--"}
                </Descriptions.Item>

                <Descriptions.Item label="MD5 Hash">
                  {fileMeta?.md5 ?? "--"}
                </Descriptions.Item>
                <Descriptions.Item label="SHA-256">
                  {fileMeta?.sha256 ?? "--"}
                </Descriptions.Item>
                <Descriptions.Item label="Upload Time">
                  {fileMeta?.uploadTime ?? "--"}
                </Descriptions.Item>

                <Descriptions.Item label="Uploader">
                  {fileMeta?.uploader ?? "--"}
                </Descriptions.Item>
                <Descriptions.Item label="Source">
                  {fileMeta?.source ?? "--"}
                </Descriptions.Item>
                <Descriptions.Item label="OS Target">
                  {fileMeta?.osTarget ?? "--"}
                </Descriptions.Item>
              </Descriptions>
            )}
          </Card>
        </Col>

        {/* DETECTION INFO */}
        <Col xs={24} lg={10}>
          <Card title="Detection Information">
            {loading ? (
              <Skeleton active paragraph={{ rows: 4 }} />
            ) : (
              <Space direction="vertical" size={10} style={{ width: "100%" }}>
                <Row justify="space-between">
                  <Col>
                    <Text type="secondary">Ransomware Family</Text>
                  </Col>
                  <Col>
                    <Text strong>{detection?.family ?? "--"}</Text>
                  </Col>
                </Row>

                <Row justify="space-between">
                  <Col>
                    <Text type="secondary">Variant</Text>
                  </Col>
                  <Col>
                    <Text strong>{detection?.variant ?? "--"}</Text>
                  </Col>
                </Row>

                <Row justify="space-between">
                  <Col>
                    <Text type="secondary">Detection Model</Text>
                  </Col>
                  <Col>
                    <Text strong>{detection?.model ?? "--"}</Text>
                  </Col>
                </Row>

                <Divider style={{ margin: "4px 0" }} />

                <Row justify="space-between">
                  <Col>
                    <Text type="secondary">Model Confidence (Malicious)</Text>
                  </Col>
                  <Col>
                    <Text strong>
                      {detection?.modelConfidenceMalicious != null
                        ? `${normalizePct(detection.modelConfidenceMalicious)}%`
                        : confidencePct
                        ? `${confidencePct}%`
                        : "--"}
                    </Text>
                  </Col>
                </Row>

                <Row justify="space-between">
                  <Col>
                    <Text type="secondary">Model Confidence (Benign)</Text>
                  </Col>
                  <Col>
                    <Text strong>
                      {detection?.modelConfidenceBenign != null
                        ? `${normalizePct(detection.modelConfidenceBenign)}%`
                        : "--"}
                    </Text>
                  </Col>
                </Row>
              </Space>
            )}
          </Card>
        </Col>

        {/* MALICIOUS BEHAVIOR TIMELINE */}
        <Col xs={24} lg={14}>
          <Card title="Malicious Behavior Timeline">
            {loading ? (
              <Skeleton active paragraph={{ rows: 4 }} />
            ) : data.behaviorTimeline.length === 0 ? (
              <Empty description="No behavior timeline." />
            ) : (
              <Timeline items={timelineItems} />
            )}
          </Card>
        </Col>

        {/* ATTACK CHAIN VISUALIZATION */}
        <Col xs={24} lg={10}>
          <Card title="Attack Chain Visualization">
            {loading ? (
              <Skeleton active paragraph={{ rows: 3 }} />
            ) : attackNodes.length === 0 ? (
              <Empty description="No attack chain data." />
            ) : (
              <AttackChain nodes={attackNodes} />
            )}
          </Card>
        </Col>
      </Row>

      <Divider />

      <div style={{ textAlign: "center", fontSize: 11, color: "#6b7280" }}>
        © {new Date().getFullYear()} CyberGuard AI. All rights reserved.
      </div>
    </div>
  );
}

/* ----------------- Attack chain block ----------------- */

function AttackChain({ nodes = [] }) {
  return (
    <div
      style={{
        display: "grid",
        gap: 10,
      }}
    >
      {nodes.map((n, idx) => (
        <div key={n.key ?? idx}>
          <div
            style={{
              border: "1px solid #e5e7eb",
              borderRadius: 10,
              padding: "10px 12px",
              background: "#fafafa",
            }}
          >
            <Space direction="vertical" size={0}>
              <Text strong>{n.label}</Text>
              {n.subLabel ? (
                <Text type="secondary" style={{ fontSize: 11 }}>
                  {n.subLabel}
                </Text>
              ) : null}
            </Space>
          </div>

          {idx < nodes.length - 1 && (
            <div
              style={{
                height: 14,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#9ca3af",
                fontSize: 10,
              }}
            >
              ↓
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
