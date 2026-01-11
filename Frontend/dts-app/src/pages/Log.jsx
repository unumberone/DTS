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

const API_BASE = process.env.REACT_APP_API_BASE_URL || "";

async function getLogs(params = {}, { signal } = {}) {
  const qs = new URLSearchParams();

  if (params.start) qs.set("start", params.start);
  if (params.end) qs.set("end", params.end);
  if (params.source) qs.set("source", params.source);
  if (params.eventType) qs.set("eventType", params.eventType);
  if (params.severity) qs.set("severity", params.severity);
  if (params.keyword) qs.set("keyword", params.keyword);
  if (params.page) qs.set("page", String(params.page));
  if (params.pageSize) qs.set("pageSize", String(params.pageSize));

  const url = `${API_BASE}/api/logs${qs.toString() ? `?${qs}` : ""}`;

  const res = await fetch(url, { signal });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || "Failed to load logs");
  }

  const json = await res.json();
  const rawList = Array.isArray(json) ? json : (json?.items || []);

  // Map to Log items (simulating Sysmon format as requested)
  // Backend returns: { filename, result, details, timestamp, id, ... }
  const items = rawList.slice().reverse().map((item, index) => {
    const isSus = item.result !== "Benign" && item.result !== "Clean";
    return {
      id: item.id || index.toString(),
      timestamp: item.timestamp,
      source: "Sysmon",
      eventId: 11, // FileCreate
      eventType: "File Create (Rule: RansomwareDetection)",
      severity: isSus ? (item.result === "Suspicious" ? "Medium" : "Critical") : "Informational",
      message: `File created: ${item.filename} | Detection: ${item.result}`,
      raw: JSON.stringify(item, null, 2),
      parsed: {
        image: "C:\\Windows\\Explorer.EXE",
        targetFilename: `D:\\Uploads\\${item.filename}`,
        detectionResult: item.result,
        confidence: item.confidence,
        details: item.details
      },
      insights: [item.details]
    };
  });

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

const LOG_SOURCES = ["Sysmon", "Firewall", "Application", "Windows Security"];
const EVENT_TYPES = [
  "Process Creation",
  "Network Connection",
  "File Modification",
  "Registry Access",
];
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];

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
        source: values?.source,
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
            source: undefined,
            eventType: undefined,
            severity: undefined,
            keyword: "",
            range: null,
          }}
        >
          <Row gutter={[12, 12]} align="bottom">
            <Col xs={24} md={7} lg={6}>
              <Form.Item label="Date Range" name="range">
                <RangePicker className="w-full" />
              </Form.Item>
            </Col>

            <Col xs={24} md={5} lg={4}>
              <Form.Item label="Log Source" name="source">
                <Select
                  allowClear
                  placeholder="Select source"
                  options={LOG_SOURCES.map((s) => ({ value: s, label: s }))}
                />
              </Form.Item>
            </Col>

            <Col xs={24} md={5} lg={4}>
              <Form.Item label="Event Type" name="eventType">
                <Select
                  allowClear
                  placeholder="Select type"
                  options={EVENT_TYPES.map((s) => ({ value: s, label: s }))}
                />
              </Form.Item>
            </Col>

            <Col xs={24} md={4} lg={3}>
              <Form.Item label="Severity" name="severity">
                <Select
                  allowClear
                  placeholder="Severity"
                  options={SEVERITIES.map((s) => ({ value: s, label: s }))}
                />
              </Form.Item>
            </Col>

            <Col xs={24} md={7} lg={5}>
              <Form.Item label="Keywords / Process Names" name="keyword">
                <Input
                  allowClear
                  placeholder="Search / Process Names"
                  prefix={<SearchOutlined />}
                />
              </Form.Item>
            </Col>

            <Col xs={24} md={8} lg={2}>
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
