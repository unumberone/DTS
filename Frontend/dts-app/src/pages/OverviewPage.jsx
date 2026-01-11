import React, { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Empty,
  List,
  Progress,
  Row,
  Skeleton,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
} from "antd";
import {
  FileSearchOutlined,
  SafetyCertificateOutlined,
  AimOutlined,
  ClockCircleOutlined,
  ReloadOutlined,
  ExportOutlined,
} from "@ant-design/icons";
import { getOverview } from "../api/overviewApi";

const { Title, Text } = Typography;

const numberFmt = new Intl.NumberFormat();

const normalizeResult = (v) =>
  String(v || "")
    .trim()
    .toLowerCase() === "malicious"
    ? "malicious"
    : "benign";

const normalizePercent = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0;
  const pct = n <= 1 ? n * 100 : n;
  return Math.max(0, Math.min(100, Math.round(pct)));
};

export default function OverviewPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [overview, setOverview] = useState({
    stats: null,
    threats: [],
    detectionsOverTime: [],
    categories: [],
    alertBreakdown: [],
    recentAlerts: [],
  });

  const fetchData = () => {
    const ac = new AbortController();

    setLoading(true);
    setError("");

    getOverview({ signal: ac.signal })
      .then((json) => {
        const categories = Array.isArray(json?.categories) ? json.categories : [];

        const alertBreakdown =
          (Array.isArray(json?.alertBreakdown) && json.alertBreakdown) ||
          (Array.isArray(json?.alertPanel) && json.alertPanel) ||
          (Array.isArray(json?.alertsByType) && json.alertsByType) ||
          [];

        setOverview({
          stats: json?.stats ?? null,
          threats: Array.isArray(json?.threats) ? json.threats : [],
          detectionsOverTime: Array.isArray(json?.detectionsOverTime)
            ? json.detectionsOverTime
            : [],
          categories,
          alertBreakdown: alertBreakdown.length ? alertBreakdown : categories,
          recentAlerts: Array.isArray(json?.recentAlerts) ? json.recentAlerts : [],
        });
      })
      .catch((e) => {
        if (e?.name !== "AbortError") setError(e?.message || "Load failed");
      })
      .finally(() => setLoading(false));

    return () => ac.abort();
  };

  useEffect(() => {
    const cancel = fetchData();
    return cancel;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const statCards = useMemo(() => {
    const s = overview.stats;

    const scannedValue =
      s?.totalScannedToday != null ? numberFmt.format(s.totalScannedToday) : "--";
    const scannedSub =
      s?.scannedDeltaPct != null
        ? `${s.scannedDeltaPct > 0 ? "+" : ""}${s.scannedDeltaPct}% from yesterday`
        : "--";

    const maliciousValue =
      s?.maliciousDetected != null ? numberFmt.format(s.maliciousDetected) : "--";

    const rateValue =
      typeof s?.detectionRatePct === "number"
        ? `${s.detectionRatePct.toFixed(1)}%`
        : "--";
    const rateSub =
      typeof s?.detectionCiLowPct === "number" &&
      typeof s?.detectionCiHighPct === "number"
        ? `CI: ${s.detectionCiLowPct}% – ${s.detectionCiHighPct}%`
        : "--";

    const avgValue =
      typeof s?.avgScanTimeSec === "number"
        ? `${s.avgScanTimeSec.toFixed(1)}s`
        : "--";
    const avgSub =
      s?.avgFileSizeMb != null ? `Avg file size ${s.avgFileSizeMb}MB` : "--";

    return [
      {
        key: "scanned",
        title: "Total files scanned today",
        value: scannedValue,
        sub: scannedSub,
        icon: <FileSearchOutlined />,
      },
      {
        key: "malicious",
        title: "Detected malicious files",
        value: maliciousValue,
        sub: "Critical threats found",
        icon: <SafetyCertificateOutlined />,
      },
      {
        key: "rate",
        title: "Detection rate",
        value: rateValue,
        sub: rateSub,
        icon: <AimOutlined />,
      },
      {
        key: "avg",
        title: "Average scan time",
        value: avgValue,
        sub: avgSub,
        icon: <ClockCircleOutlined />,
      },
    ];
  }, [overview.stats]);

  const totalMalicious = useMemo(() => {
    if (overview.stats?.maliciousDetected != null) {
      return overview.stats.maliciousDetected;
    }
    return overview.threats.filter((t) => normalizeResult(t?.result) === "malicious")
      .length;
  }, [overview.stats, overview.threats]);

  const threatColumns = useMemo(
    () => [
      {
        title: "File Name",
        dataIndex: "fileName",
        key: "fileName",
        ellipsis: true,
        render: (v) => v ?? "--",
      },
      {
        title: "Type",
        dataIndex: "type",
        key: "type",
        width: 90,
        render: (v) => v ?? "--",
      },
      {
        title: "Size",
        dataIndex: "sizeLabel",
        key: "sizeLabel",
        width: 110,
        render: (v) => v ?? "--",
      },
      {
        title: "Result",
        dataIndex: "result",
        key: "result",
        width: 110,
        render: (v) => {
          const r = normalizeResult(v);
          return (
            <Tag color={r === "malicious" ? "red" : "green"}>
              {r === "malicious" ? "Malicious" : "Benign"}
            </Tag>
          );
        },
      },
      {
        title: "Confidence",
        dataIndex: "confidence",
        key: "confidence",
        width: 170,
        render: (v, row) => {
          const pct = normalizePercent(v);
          const bad = normalizeResult(row?.result) === "malicious";
          return (
            <Progress
              percent={pct}
              size="small"
              status={bad ? "exception" : "normal"}
              showInfo
            />
          );
        },
      },
      {
        title: "Timestamp",
        dataIndex: "timestamp",
        key: "timestamp",
        width: 160,
        render: (v) => v ?? "--",
      },
      {
        title: "Uploader",
        dataIndex: "uploader",
        key: "uploader",
        width: 120,
        render: (v) => v ?? "--",
      },
    ],
    []
  );

  return (
    <div>
      <Space
        direction="vertical"
        size={14}
        style={{ width: "100%" }}
      >
        <Row justify="space-between" align="middle">
          <Col>
            <Title level={3} style={{ marginBottom: 0 }}>
              Overview
            </Title>
            <Text type="secondary">
              High-level status of ransomware detection and file scans.
            </Text>
          </Col>
          <Col>
            <Space>
              <Button
                icon={<ReloadOutlined />}
                onClick={fetchData}
                loading={loading}
              >
                Refresh
              </Button>
            </Space>
          </Col>
        </Row>

        {error && (
          <Alert
            type="error"
            showIcon
            message="Failed to load overview"
            description={error}
          />
        )}

        <Row gutter={[12, 12]}>
          {statCards.map((c) => (
            <Col key={c.key} xs={24} sm={12} lg={6}>
              <Card>
                {loading ? (
                  <Skeleton active paragraph={{ rows: 1 }} />
                ) : (
                  <Space align="start">
                    <span style={{ fontSize: 22, color: "#1677ff" }}>
                      {c.icon}
                    </span>
                    <div>
                      <Text type="secondary">{c.title}</Text>
                      <Statistic
                        value={c.value}
                        valueStyle={{ fontSize: 24, marginTop: 2 }}
                      />
                      <Text type="secondary">{c.sub}</Text>
                    </div>
                  </Space>
                )}
              </Card>
            </Col>
          ))}
        </Row>

        <Row gutter={[12, 12]}>
          <Col xs={24} lg={14}>
            <Card
              title="Threat Status Panel"
              extra={<Text type="secondary">Hover for details</Text>}
            >
              <Table
                rowKey={(r, i) => r?.id ?? i}
                columns={threatColumns}
                dataSource={overview.threats}
                loading={loading}
                size="middle"
                pagination={{ pageSize: 6 }}
                locale={{
                  emptyText: loading ? "Loading..." : "No threat records.",
                }}
              />
            </Card>
          </Col>

          <Col xs={24} lg={10}>
            <Row gutter={[12, 12]}>
              <Col span={24}>
                <Card title="Detections Over Time">
                  <DetectionsMiniChart
                    loading={loading}
                    data={overview.detectionsOverTime}
                  />
                </Card>
              </Col>

              <Col span={24}>
                <Card title="Alert Panel">
                  <CategoryBreakdown
                    loading={loading}
                    total={totalMalicious || 0}
                    items={overview.alertBreakdown}
                  />
                </Card>
              </Col>
            </Row>
          </Col>
        </Row>

        <Row gutter={[12, 12]}>
          <Col xs={24} lg={14}>
            <Card title="Ransomware Categories">
              <CategoryBreakdown
                loading={loading}
                total={totalMalicious || 0}
                items={overview.categories}
              />
            </Card>
          </Col>

          <Col xs={24} lg={10}>
            <Card
              title="Recent Alerts"
              extra={
                <Space>
                  <Button size="small">View details</Button>
                  <Button size="small" type="primary" icon={<ExportOutlined />}>
                    Export report
                  </Button>
                </Space>
              }
            >
              {loading ? (
                <Skeleton active paragraph={{ rows: 4 }} />
              ) : overview.recentAlerts.length === 0 ? (
                <Empty description="No recent alerts." />
              ) : (
                <List
                  itemLayout="vertical"
                  dataSource={overview.recentAlerts}
                  renderItem={(a, i) => (
                    <List.Item key={a?.id ?? i}>
                      <Space direction="vertical" size={2}>
                        <Tag color="red">{a?.label ?? "ALERT"}</Tag>
                        <Text>{a?.desc ?? ""}</Text>
                      </Space>
                    </List.Item>
                  )}
                />
              )}
            </Card>
          </Col>
        </Row>
      </Space>
    </div>
  );
}

/* --------- Small UI blocks (no hardcode data) --------- */

function CategoryBreakdown({ total = 0, items = [], loading }) {
  const normalized = useMemo(() => {
    const arr = Array.isArray(items) ? items : [];
    const sum = arr.reduce((s, it) => s + (Number(it?.value) || 0), 0);

    return arr.map((it) => {
      const raw = Number(it?.value) || 0;
      const pct = sum > 0 ? Math.round((raw / sum) * 100) : 0;
      return {
        label: it?.label ?? "Unknown",
        raw,
        pct,
      };
    });
  }, [items]);

  if (loading) {
    return <Skeleton active paragraph={{ rows: 3 }} />;
  }

  return (
    <Row gutter={[12, 12]} align="middle">
      <Col xs={24} sm={8}>
        <div style={{ display: "flex", justifyContent: "center" }}>
          <Progress
            type="circle"
            percent={100}
            format={() => (
              <div style={{ lineHeight: 1.1 }}>
                <div style={{ fontSize: 11, color: "#6b7280" }}>Total</div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>{total}</div>
              </div>
            )}
          />
        </div>
      </Col>
      <Col xs={24} sm={16}>
        {normalized.length === 0 ? (
          <Empty description="No category data." />
        ) : (
          <Space direction="vertical" size={8} style={{ width: "100%" }}>
            {normalized.map((it, i) => (
              <div key={i}>
                <Row justify="space-between">
                  <Col>
                    <Text>{it.label}</Text>
                  </Col>
                  <Col>
                    <Text type="secondary">{it.pct}%</Text>
                  </Col>
                </Row>
                <Progress percent={it.pct} size="small" />
              </div>
            ))}
          </Space>
        )}
      </Col>
    </Row>
  );
}

function DetectionsMiniChart({ loading, data = [] }) {
  if (loading) return <Skeleton active paragraph={{ rows: 2 }} />;

  if (!Array.isArray(data) || data.length === 0) {
    return <Empty description="No chart data" />;
  }

  const width = 520;
  const height = 180;
  const pad = 22;

  const safeNum = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

  const benign = data.map((d) => safeNum(d?.benign));
  const malicious = data.map((d) => safeNum(d?.malicious));
  const max = Math.max(10, ...benign, ...malicious);

  const xStep = (width - pad * 2) / (data.length - 1 || 1);

  const yScale = (v) =>
    height - pad - (v / (max || 1)) * (height - pad * 2);

  const makePath = (arr) =>
    arr
      .map((v, i) => {
        const x = pad + i * xStep;
        const y = yScale(v);
        return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
      })
      .join(" ");

  const benignPath = makePath(benign);
  const maliciousPath = makePath(malicious);

  return (
    <div style={{ width: "100%", overflowX: "auto" }}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: "100%", height: "auto" }}
      >
        {[0, 1, 2, 3].map((g) => {
          const y = pad + g * ((height - pad * 2) / 3);
          return (
            <line
              key={g}
              x1={pad}
              x2={width - pad}
              y1={y}
              y2={y}
              stroke="#eef2f7"
              strokeWidth="1"
            />
          );
        })}

        <line
          x1={pad}
          x2={pad}
          y1={pad}
          y2={height - pad}
          stroke="#d9dee7"
        />
        <line
          x1={pad}
          x2={width - pad}
          y1={height - pad}
          y2={height - pad}
          stroke="#d9dee7"
        />

        <path
          d={benignPath}
          fill="none"
          stroke="#1677ff"
          strokeWidth="2"
        />
        <path
          d={maliciousPath}
          fill="none"
          stroke="#ff4d4f"
          strokeWidth="2"
        />

        {data.map((d, i) => {
          if (i % 2 !== 0) return null;
          const x = pad + i * xStep;
          return (
            <text
              key={i}
              x={x}
              y={height - 6}
              textAnchor="middle"
              fontSize="10"
              fill="#6b7280"
            >
              {d?.t ?? ""}
            </text>
          );
        })}
      </svg>

      <Space size={10} style={{ marginTop: 8 }}>
        <Tag color="blue">Benign</Tag>
        <Tag color="red">Malicious</Tag>
      </Space>
    </div>
  );
}
