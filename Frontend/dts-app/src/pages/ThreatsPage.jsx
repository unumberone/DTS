// src/pages/ThreatsPage.jsx
import React, { useEffect, useState } from "react";
import { Alert, Card, Table, Tag, Typography, Skeleton, Progress } from "antd";
import { useNavigate } from "react-router-dom";
import { getThreats } from "../api/threatApi";

const { Title, Text } = Typography;

const normalizeResult = (v) =>
  String(v || "").trim().toLowerCase() === "malicious" ? "malicious" : "benign";

const normalizePct = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0;
  const pct = n <= 1 ? n * 100 : n;
  return Math.max(0, Math.min(100, Math.round(pct)));
};

export default function ThreatsPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [rows, setRows] = useState([]);

  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    setError("");

    getThreats({ signal: ac.signal })
      .then((json) => {
        setRows(Array.isArray(json) ? json : json?.items ?? []);
      })
      .catch((e) => {
        if (e?.name !== "AbortError") setError(e?.message || "Load failed");
      })
      .finally(() => setLoading(false));

    return () => ac.abort();
  }, []);

  const columns = [
    {
      title: "File Name",
      dataIndex: "fileName",
      key: "fileName",
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
      title: "Result",
      dataIndex: "result",
      key: "result",
      width: 120,
      render: (v) => {
        const r = normalizeResult(v);
        return <Tag color={r === "malicious" ? "red" : "green"}>{r}</Tag>;
      },
    },
    {
      title: "Confidence",
      dataIndex: "confidencePct",
      key: "confidencePct",
      width: 180,
      render: (v, row) => {
        const pct = normalizePct(v ?? row?.confidence);
        return (
          <Progress
            percent={pct}
            size="small"
            status={normalizeResult(row?.result) === "malicious" ? "exception" : "normal"}
          />
        );
      },
    },
    {
      title: "Timestamp",
      dataIndex: "timestamp",
      key: "timestamp",
      width: 170,
      render: (v) => v ?? "--",
    },
    {
      title: "Uploader",
      dataIndex: "uploader",
      key: "uploader",
      width: 140,
      render: (v) => v ?? "--",
    },
  ];

  return (
    <div>
      <Title level={4} style={{ marginBottom: 4 }}>
        Threats
      </Title>
      <Text type="secondary">
        Danh sách các file được hệ thống đánh giá rủi ro.
      </Text>

      {error && (
        <Alert
          style={{ marginTop: 12 }}
          type="error"
          showIcon
          message="Failed to load threats"
          description={error}
        />
      )}

      <Card style={{ marginTop: 12 }}>
        {loading ? (
          <Skeleton active paragraph={{ rows: 6 }} />
        ) : (
          <Table
            rowKey={(r, idx) => r.id ?? r.sha256 ?? idx}
            columns={columns}
            dataSource={rows}
            pagination={{ pageSize: 8 }}
            onRow={(record) => ({
              onClick: () => {
                if (record?.id) navigate(`/threats/${record.id}`);
              },
            })}
          />
        )}
      </Card>
    </div>
  );
}
