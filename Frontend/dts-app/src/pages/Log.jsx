import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Card,
  Row,
  Col,
  Form,
  DatePicker,
  Select,
  Input,
  Button,
  Table,
  Tag,
  Space,
  Drawer,
  Tabs,
  Descriptions,
  Typography,
  Alert,
  message,
  Spin,
  Empty,
} from "antd";
import {
  FilterOutlined,
  ReloadOutlined,
  SearchOutlined,
  ExportOutlined,
} from "@ant-design/icons";
import "../css/log.css";

const { RangePicker } = DatePicker;
const { Text } = Typography;

const API_BASE = process.env.REACT_APP_API_BASE_URL || "http://localhost:8000";
console.log("[Log.jsx] API_BASE:", API_BASE);

async function getLogs(params = {}, { signal } = {}) {
  const url = `${API_BASE}/api/logs`;
  console.log("[Log.jsx] Fetching:", url);

  const res = await fetch(url, { signal });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || "Failed to load logs");
  }

  const json = await res.json();
  let rawList = Array.isArray(json) ? json : (json?.items || []);

  // Backend returns: { filename, result, details, timestamp, id, confidence, type, uploader, ... }
  // Transform to log format
  let items = rawList.slice().reverse().map((item, index) => {
    const result = item.result || "Unknown";
    const isMalicious = result === "Malicious" || result === "MALICIOUS";
    const isSuspicious = result === "Suspicious" || result === "SUSPICIOUS";

    // Determine severity based on result
    let severity = "Informational";
    if (isMalicious) severity = "Critical";
    else if (isSuspicious) severity = "Medium";

    // Determine event type based on result
    let eventType = "File Scan";
    if (isMalicious) eventType = "Malware Detected";
    else if (isSuspicious) eventType = "Suspicious Activity";

    return {
      id: item.id || index.toString(),
      timestamp: item.timestamp,
      source: "DTS Scanner",
      eventId: isMalicious ? 1 : (isSuspicious ? 2 : 0),
      eventType: eventType,
      severity: severity,
      result: result,
      filename: item.filename || "Unknown",
      message: `File: ${item.filename} | Result: ${result} | Confidence: ${item.confidence || 0}%`,
      raw: JSON.stringify(item, null, 2),
      parsed: {
        filename: item.filename,
        result: result,
        confidence: item.confidence,
        type: item.type || "unknown",
        uploader: item.uploader || "admin",
        details: item.details
      },
      insights: item.details ? [item.details] : []
    };
  });

  // ===== CLIENT-SIDE FILTERING =====

  // Date Range filter
  if (params.start && params.end) {
    const startDate = new Date(params.start);
    const endDate = new Date(params.end);
    items = items.filter(item => {
      const itemDate = new Date(item.timestamp);
      return itemDate >= startDate && itemDate <= endDate;
    });
  }

  // Result filter (using eventType)
  if (params.eventType) {
    items = items.filter(item => item.eventType === params.eventType);
  }

  // Severity filter
  if (params.severity) {
    items = items.filter(item => item.severity === params.severity);
  }

  // Keyword filter (search in filename and message)
  if (params.keyword) {
    const kw = params.keyword.toLowerCase();
    items = items.filter(item =>
      item.filename?.toLowerCase().includes(kw) ||
      item.message?.toLowerCase().includes(kw) ||
      item.result?.toLowerCase().includes(kw)
    );
  }

  return { items, total: items.length };
}

// fallback demo (chỉ để tránh page trắng khi chưa có backend)
const MOCK_LOGS = [
  {
    id: "1",
    timestamp: "2023-10-27 10:32:45",
    source: "Sysmon",
    eventId: 1,
    eventType: "Process Creation",
    severity: "High",
    message: "Process created: C:\\Windows\\System32\\cmd.exe",
    raw: "Raw event payload ...",
    parsed: {
      processGuid: "{1234-...}",
      processId: 5648,
      image: "C:\\Windows\\System32\\cmd.exe",
      commandLine: "cmd.exe /c powershell ...",
      parentImage: "C:\\Windows\\explorer.exe",
    },
    insights: [
      "Related to ransomware activity.",
      "Suspicious PowerShell chain detected.",
    ],
  },
];

// Filter options matched to DTS data
const EVENT_TYPES = [
  "File Scan",
  "Malware Detected",
  "Suspicious Activity",
];
const SEVERITIES = ["Critical", "Medium", "Informational"];

function severityTag(sev) {
  const v = String(sev || "").toLowerCase();
  if (v === "critical") return <Tag color="red">Critical</Tag>;
  if (v === "high") return <Tag color="volcano">High</Tag>;
  if (v === "medium") return <Tag color="orange">Medium</Tag>;
  if (v === "low") return <Tag color="blue">Low</Tag>;
  return <Tag>Informational</Tag>;
}

function normalizeKeyword(v) {
  const s = String(v || "").trim();
  return s.length ? s : "";
}

export default function Log() {
  const [form] = Form.useForm();
  const abortRef = useRef(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selected, setSelected] = useState(null);

  const buildParamsFromForm = useCallback(
    (values) => {
      const range = values?.range;
      const start = range?.[0]?.toISOString?.();
      const end = range?.[1]?.toISOString?.();

      return {
        start,
        end,
        eventType: values?.eventType,
        severity: values?.severity,
        keyword: normalizeKeyword(values?.keyword),
      };
    },
    []
  );

  const loadLogs = useCallback(
    async ({ nextPage = page, nextPageSize = pageSize } = {}) => {
      const values = form.getFieldsValue();
      const filterParams = buildParamsFromForm(values);

      abortRef.current?.abort?.();
      const ac = new AbortController();
      abortRef.current = ac;

      setLoading(true);
      setError("");

      try {
        const result = await getLogs(
          {
            ...filterParams,
            page: nextPage,
            pageSize: nextPageSize,
          },
          { signal: ac.signal }
        );

        setRows(result.items);
        setTotal(result.total);
      } catch (e) {
        if (e?.name !== "AbortError") {
          const msg = e?.message || "Load failed";
          setError(msg);

          // fallback mock
          setRows(MOCK_LOGS);
          setTotal(MOCK_LOGS.length);
        }
      } finally {
        setLoading(false);
      }
    },
    [form, buildParamsFromForm, page, pageSize]
  );

  useEffect(() => {
    loadLogs({ nextPage: 1, nextPageSize: pageSize });
    setPage(1);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const onApply = () => {
    setPage(1);
    loadLogs({ nextPage: 1, nextPageSize: pageSize });
  };

  const onReset = () => {
    form.resetFields();
    setPage(1);
    loadLogs({ nextPage: 1, nextPageSize: pageSize });
  };

  const columns = useMemo(
    () => [
      {
        title: "Timestamp",
        dataIndex: "timestamp",
        key: "timestamp",
        width: 170,
      },
      {
        title: "Log Source",
        dataIndex: "source",
        key: "source",
        width: 140,
      },
      {
        title: "Event ID",
        dataIndex: "eventId",
        key: "eventId",
        width: 90,
      },
      {
        title: "Event Type",
        dataIndex: "eventType",
        key: "eventType",
        width: 170,
      },
      {
        title: "Severity",
        dataIndex: "severity",
        key: "severity",
        width: 120,
        render: (_, r) => severityTag(r.severity),
      },
      {
        title: "Message / Description",
        dataIndex: "message",
        key: "message",
        ellipsis: true,
      },
    ],
    []
  );

  const handleRowClick = (record) => {
    setSelected(record);
    setDrawerOpen(true);
  };

  const handleExport = () => {
    if (!rows || rows.length === 0) {
      message.warning("No logs to export.");
      return;
    }

    const header = ["Timestamp", "Source", "EventID", "EventType", "Severity", "Message", "Details"];
    const csvRows = [header.join(",")];

    rows.forEach(row => {
      const line = [
        `"${row.timestamp}"`,
        `"${row.source}"`,
        `"${row.eventId}"`,
        `"${row.eventType}"`,
        `"${row.severity}"`,
        `"${row.message.replace(/"/g, '""')}"`, // Escape quotes
        `"${(row.insights || []).join('; ')}"`
      ];
      csvRows.push(line.join(","));
    });

    const csvContent = "data:text/csv;charset=utf-8," + encodeURI(csvRows.join("\n"));
    const link = document.createElement("a");
    link.setAttribute("href", csvContent);
    link.setAttribute("download", `log_export_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    message.success("Logs exported successfully.");
  };

  return (
    <div className="cg-log">
      <div className="cg-log__head">
        <div>
          <h1 className="cg-log__title">Log Analysis</h1>
          <p className="cg-log__subtitle">
            Explore and analyze security logs from various sources.
          </p>
        </div>
      </div>

      <Card className="cg-log__filters" bordered={false}>
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            eventType: undefined,
            severity: undefined,
            keyword: "",
            range: null,
          }}
        >
          <Row gutter={[16, 0]} align="middle">
            <Col xs={24} md={6} lg={5}>
              <Form.Item label="Date Range" name="range" style={{ marginBottom: 0 }}>
                <RangePicker className="w-full" />
              </Form.Item>
            </Col>

            <Col xs={24} md={5} lg={4}>
              <Form.Item label="Event Type" name="eventType" style={{ marginBottom: 0 }}>
                <Select
                  allowClear
                  placeholder="All Events"
                  options={EVENT_TYPES.map((s) => ({ value: s, label: s }))}
                />
              </Form.Item>
            </Col>

            <Col xs={24} md={4} lg={3}>
              <Form.Item label="Severity" name="severity" style={{ marginBottom: 0 }}>
                <Select
                  allowClear
                  placeholder="All"
                  options={SEVERITIES.map((s) => ({ value: s, label: s }))}
                />
              </Form.Item>
            </Col>

            <Col xs={24} md={6} lg={5}>
              <Form.Item label="Search Keywords" name="keyword" style={{ marginBottom: 0 }}>
                <Input
                  allowClear
                  placeholder="Filename, result..."
                  prefix={<SearchOutlined />}
                />
              </Form.Item>
            </Col>

            <Col xs={24} md={3} lg={4}>
              <Form.Item label=" " style={{ marginBottom: 0 }}>
                <Space>
                  <Button
                    type="primary"
                    icon={<FilterOutlined />}
                    onClick={onApply}
                  >
                    Apply
                  </Button>
                  <Button icon={<ReloadOutlined />} onClick={onReset}>
                    Reset
                  </Button>
                </Space>
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Card>

      {error && (
        <Alert
          className="cg-log__error"
          type="warning"
          showIcon
          message="API warning"
          description={error}
        />
      )}

      <Card className="cg-log__table-card" bordered={false}>
        <Spin spinning={loading}>
          <Table
            rowKey={(r) => r.id ?? `${r.timestamp}-${r.eventId}`}
            columns={columns}
            dataSource={rows}
            pagination={{
              current: page,
              pageSize,
              total,
              showSizeChanger: true,
              onChange: (p, ps) => {
                setPage(p);
                setPageSize(ps);
                loadLogs({ nextPage: p, nextPageSize: ps });
              },
            }}
            locale={{
              emptyText: (
                <Empty description="No logs found with current filters." />
              ),
            }}
            onRow={(record) => ({
              onClick: () => handleRowClick(record),
            })}
            className="cg-log__table"
          />
        </Spin>
      </Card>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={420}
        className="cg-log__drawer"
        title={
          <span>
            Log Details{" "}
            <Text type="secondary">
              - Event ID {selected?.eventId ?? selected?.id ?? "--"}
            </Text>
          </span>
        }
        extra={
          <Space>
            <Button icon={<ExportOutlined />} onClick={handleExport}>
              Export
            </Button>
            <Button onClick={() => setDrawerOpen(false)}>Close</Button>
          </Space>
        }
      >
        {!selected ? (
          <Empty description="Select a log row to view details." />
        ) : (
          <Tabs
            defaultActiveKey="parsed"
            items={[
              {
                key: "raw",
                label: "Raw Log",
                children: (
                  <Card size="small" bordered={false}>
                    <pre className="cg-log__raw">
                      {selected?.raw || selected?.message || "--"}
                    </pre>
                  </Card>
                ),
              },
              {
                key: "parsed",
                label: "Parsed Data",
                children: (
                  <Descriptions
                    size="small"
                    column={1}
                    bordered
                    className="cg-log__desc"
                  >
                    <Descriptions.Item label="UtcTime">
                      {selected?.timestamp ?? "--"}
                    </Descriptions.Item>
                    <Descriptions.Item label="ProcessGuid">
                      {selected?.parsed?.processGuid ?? "--"}
                    </Descriptions.Item>
                    <Descriptions.Item label="ProcessId">
                      {selected?.parsed?.processId ?? "--"}
                    </Descriptions.Item>
                    <Descriptions.Item label="Image">
                      {selected?.parsed?.image ?? "--"}
                    </Descriptions.Item>
                    <Descriptions.Item label="CommandLine">
                      {selected?.parsed?.commandLine ?? "--"}
                    </Descriptions.Item>
                    <Descriptions.Item label="ParentImage">
                      {selected?.parsed?.parentImage ?? "--"}
                    </Descriptions.Item>
                    <Descriptions.Item label="Source">
                      {selected?.source ?? "--"}
                    </Descriptions.Item>
                    <Descriptions.Item label="EventType">
                      {selected?.eventType ?? "--"}
                    </Descriptions.Item>
                    <Descriptions.Item label="Severity">
                      {severityTag(selected?.severity)}
                    </Descriptions.Item>
                  </Descriptions>
                ),
              },
              {
                key: "insights",
                label: "Correlation Insights",
                children: (
                  <Space direction="vertical" className="w-full">
                    {(selected?.insights || []).length === 0 && (
                      <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="No correlation insights."
                      />
                    )}
                    {(selected?.insights || []).map((t, i) => (
                      <Alert
                        key={i}
                        type="error"
                        showIcon
                        message={t}
                      />
                    ))}
                  </Space>
                ),
              },
            ]}
          />
        )}
      </Drawer>
    </div>
  );
}
