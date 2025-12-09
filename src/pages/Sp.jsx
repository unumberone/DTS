import React, { useEffect, useMemo, useState } from "react";
import {
  Row,
  Col,
  Card,
  Input,
  List,
  Space,
  Button,
  Tag,
  Table,
  Typography,
  Modal,
  Form,
  Select,
  Drawer,
  Alert,
  Badge,
  message,
} from "antd";
import {
  SearchOutlined,
  RocketOutlined,
  ToolOutlined,
  ApiOutlined,
  UserOutlined,
  MailOutlined,
  MessageOutlined,
  TeamOutlined,
} from "@ant-design/icons";
import "../css/support.css";
import {
  getSupportHub,
  searchKnowledgeBase,
  createTicket,
} from "../api/supportApi";

const { Title, Text } = Typography;

const CATEGORY_ITEMS = [
  {
    key: "getting-started",
    title: "Getting Started",
    icon: <RocketOutlined />,
    desc: "Guides for new users, installation, and initial setup.",
    tags: ["onboarding", "setup"],
  },
  {
    key: "troubleshooting",
    title: "Troubleshooting",
    icon: <ToolOutlined />,
    desc: "Common issues, error codes, and self-help solutions.",
    tags: ["errors", "performance"],
  },
  {
    key: "api-integrations",
    title: "API & Integrations",
    icon: <ApiOutlined />,
    desc: "Documentation for developers and third-party connections.",
    tags: ["api", "webhooks"],
  },
  {
    key: "account",
    title: "Account Management",
    icon: <UserOutlined />,
    desc: "Manage your subscription, billing, and user permissions.",
    tags: ["account", "billing"],
  },
];

const statusColor = (s) => {
  const v = String(s || "").toLowerCase();
  if (v === "open") return "gold";
  if (v === "resolved") return "green";
  if (v === "closed") return "default";
  return "blue";
};

export default function Sp() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [hub, setHub] = useState({
    announcements: [],
    tickets: [],
    chat: { available: false },
  });

  // Search KB
  const [query, setQuery] = useState("");
  const [kbOpen, setKbOpen] = useState(false);
  const [kbLoading, setKbLoading] = useState(false);
  const [kbError, setKbError] = useState("");
  const [kbResults, setKbResults] = useState([]);

  // Category modal
  const [catOpen, setCatOpen] = useState(false);
  const [catActive, setCatActive] = useState(null);

  // Ticket modal
  const [ticketOpen, setTicketOpen] = useState(false);
  const [ticketSaving, setTicketSaving] = useState(false);
  const [ticketForm] = Form.useForm();

  // Live chat drawer
  const [chatOpen, setChatOpen] = useState(false);

  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    setError("");

    getSupportHub({ signal: ac.signal })
      .then((json) => {
        setHub({
          announcements: Array.isArray(json?.announcements)
            ? json.announcements
            : [],
          tickets: Array.isArray(json?.tickets) ? json.tickets : [],
          chat: json?.chat ?? { available: false },
        });
      })
      .catch((e) => {
        if (e?.name !== "AbortError") {
          setError(e?.message || "Failed to load support hub");
        }
      })
      .finally(() => setLoading(false));

    return () => ac.abort();
  }, []);

  const ticketColumns = useMemo(
    () => [
      {
        title: "Ticket ID",
        dataIndex: "id",
        key: "id",
        width: 140,
        render: (v) => <Text className="sp-ticket-id">#{v ?? "--"}</Text>,
      },
      {
        title: "Subject",
        dataIndex: "subject",
        key: "subject",
        render: (v) => <Text>{v ?? "--"}</Text>,
      },
      {
        title: "Status",
        dataIndex: "status",
        key: "status",
        width: 140,
        render: (v) => (
          <Tag color={statusColor(v)} className="sp-status-tag">
            {String(v || "Unknown")}
          </Tag>
        ),
      },
      {
        title: "Last Updated",
        dataIndex: "updatedAt",
        key: "updatedAt",
        width: 160,
        render: (v) => <Text type="secondary">{v ?? "--"}</Text>,
      },
    ],
    []
  );

  // -------- Search KB ----------
  const handleSearch = async (value) => {
    const q = String(value ?? query).trim();
    if (!q) {
      setKbResults([]);
      setKbError("");
      setKbOpen(true);
      return;
    }

    setKbOpen(true);
    setKbLoading(true);
    setKbError("");

    try {
      const res = await searchKnowledgeBase(q);
      setKbResults(Array.isArray(res?.items) ? res.items : []);
    } catch (e) {
      setKbError(e?.message || "Search failed");
      setKbResults([]);
    } finally {
      setKbLoading(false);
    }
  };

  const handleCategoryClick = (c) => {
    setCatActive(c);
    setCatOpen(true);
  };

  const handleQuickSearchByCategory = () => {
    if (!catActive) return;
    const seed = catActive.tags?.[0] || catActive.title;
    setQuery(seed);
    setCatOpen(false);
    handleSearch(seed);
  };

  // -------- Ticket ----------
  const openTicketModal = () => {
    ticketForm.resetFields();
    setTicketOpen(true);
  };

  const handleTicketSubmit = async () => {
    try {
      const values = await ticketForm.validateFields();
      setTicketSaving(true);

      /**
       * Backend gợi ý:
       * POST /api/support/tickets
       * body { subject, description, priority, category }
       * return { ticket, tickets? }
       */
      const res = await createTicket(values);

      if (Array.isArray(res?.tickets)) {
        setHub((prev) => ({ ...prev, tickets: res.tickets }));
      } else if (res?.ticket) {
        setHub((prev) => ({
          ...prev,
          tickets: [res.ticket, ...(prev.tickets || [])],
        }));
      }

      message.success("Ticket submitted successfully!");
      setTicketOpen(false);
    } catch (e) {
      if (e?.errorFields) return;
      message.error(e?.message || "Submit failed");
    } finally {
      setTicketSaving(false);
    }
  };

  const chatBadge = hub.chat?.available ? "Available" : "Offline";

  return (
    <div className="sp-hub">
      {/* Head */}
      <div className="sp-head">
        <Title level={4} className="sp-title">
          Support Hub
        </Title>
        <Text className="sp-subtitle">
          How can we help you today? Find answers, guides, and get in touch with
          our team.
        </Text>
      </div>

      {error && (
        <Alert
          type="warning"
          showIcon
          message="Support API warning"
          description={error}
          className="sp-error"
        />
      )}

      {/* Search */}
      <Card bordered className="sp-search-card">
        <Input.Search
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onSearch={handleSearch}
          allowClear
          placeholder="Search for knowledge base articles, FAQs, and more..."
          enterButton={<SearchOutlined />}
          size="large"
        />
      </Card>

      {/* Categories */}
      <div className="sp-section">
        <Text strong className="sp-section-title">
          Key Support Categories
        </Text>

        <Row gutter={[12, 12]} className="sp-cats">
          {CATEGORY_ITEMS.map((c) => (
            <Col key={c.key} xs={24} sm={12} lg={6}>
              <Card
                hoverable
                className="sp-cat-card"
                onClick={() => handleCategoryClick(c)}
              >
                <Space align="start">
                  <span className="sp-cat-icon">{c.icon}</span>
                  <div>
                    <Text strong className="sp-cat-title">
                      {c.title}
                    </Text>
                    <div className="sp-cat-desc">{c.desc}</div>
                  </div>
                </Space>
              </Card>
            </Col>
          ))}
        </Row>
      </div>

      {/* Updates + Contact */}
      <Row gutter={[12, 12]} className="sp-mid">
        <Col xs={24} lg={14}>
          <Card bordered className="sp-panel">
            <Space direction="vertical" size={10} style={{ width: "100%" }}>
              <Text strong>Recent Updates & Announcements</Text>

              {loading ? (
                <div className="sp-muted">Loading...</div>
              ) : !hub.announcements?.length ? (
                <div className="sp-muted">No announcements.</div>
              ) : (
                <List
                  size="small"
                  dataSource={hub.announcements}
                  renderItem={(a) => (
                    <List.Item className="sp-announce-item">
                      <Space>
                        <span className="sp-dot" />
                        <Text>{a?.title ?? "Update"}</Text>
                        {a?.isNew ? (
                          <Tag color="blue" className="sp-new-tag">
                            New
                          </Tag>
                        ) : null}
                        <Text type="secondary">
                          {a?.dateLabel ?? a?.date ?? ""}
                        </Text>
                      </Space>
                    </List.Item>
                  )}
                />
              )}
            </Space>
          </Card>
        </Col>

        <Col xs={24} lg={10}>
          <Card bordered className="sp-panel">
            <Space direction="vertical" size={12} style={{ width: "100%" }}>
              <Text strong>Contact Support</Text>

              <div className="sp-contact-row">
                <Button
                  type="primary"
                  icon={<MailOutlined />}
                  onClick={openTicketModal}
                  block
                >
                  Submit a Ticket
                </Button>

                <Button
                  icon={<MessageOutlined />}
                  onClick={() => setChatOpen(true)}
                  block
                >
                  Live Chat{" "}
                  <Badge
                    status={hub.chat?.available ? "success" : "default"}
                    text={chatBadge}
                    className="sp-chat-badge"
                  />
                </Button>
              </div>

              <Button
                icon={<TeamOutlined />}
                onClick={() => handleSearch("community")}
                block
              >
                Community Forum
              </Button>
            </Space>
          </Card>
        </Col>
      </Row>

      {/* Tickets */}
      <Card bordered className="sp-panel sp-tickets">
        <div className="sp-tickets-head">
          <Text strong>My Support Tickets</Text>
          <Button onClick={openTicketModal}>New Ticket</Button>
        </div>

        <Table
          rowKey={(r) => r?.id ?? Math.random()}
          loading={loading}
          columns={ticketColumns}
          dataSource={hub.tickets || []}
          pagination={{
            pageSize: 6,
            showSizeChanger: false,
          }}
          locale={{
            emptyText: "No tickets yet.",
          }}
          className="sp-table"
        />

        <div className="sp-tickets-footer">
          <Button type="link" onClick={() => handleSearch("tickets")}>
            View All Tickets
          </Button>
        </div>
      </Card>

      {/* -------- Category Modal -------- */}
      <Modal
        open={catOpen}
        onCancel={() => setCatOpen(false)}
        footer={[
          <Button key="close" onClick={() => setCatOpen(false)}>
            Close
          </Button>,
          <Button
            key="search"
            type="primary"
            onClick={handleQuickSearchByCategory}
          >
            Browse Guides
          </Button>,
        ]}
        title={catActive?.title || "Category"}
        destroyOnClose
      >
        <Space direction="vertical" size={8} style={{ width: "100%" }}>
          <Text>{catActive?.desc}</Text>
          <div>
            {(catActive?.tags || []).map((t) => (
              <Tag key={t}>{t}</Tag>
            ))}
          </div>
          <Text type="secondary" className="sp-muted">
            This section will be enriched once your Flask knowledge base API is
            connected.
          </Text>
        </Space>
      </Modal>

      {/* -------- Submit Ticket Modal -------- */}
      <Modal
        open={ticketOpen}
        onCancel={() => setTicketOpen(false)}
        onOk={handleTicketSubmit}
        okText="Save"
        cancelText="Cancel"
        confirmLoading={ticketSaving}
        title="Submit a Ticket"
        destroyOnClose
      >
        <Form
          form={ticketForm}
          layout="vertical"
          requiredMark={false}
          initialValues={{
            category: "troubleshooting",
            priority: "medium",
          }}
        >
          <Form.Item
            label="Category"
            name="category"
            rules={[{ required: true, message: "Please choose category" }]}
          >
            <Select
              options={CATEGORY_ITEMS.map((c) => ({
                value: c.key,
                label: c.title,
              }))}
            />
          </Form.Item>

          <Form.Item
            label="Subject"
            name="subject"
            rules={[
              { required: true, message: "Please enter subject" },
              { max: 120, message: "Subject too long" },
            ]}
          >
            <Input placeholder="E.g., Sysmon log parsing issue" />
          </Form.Item>

          <Form.Item label="Priority" name="priority">
            <Select
              options={[
                { value: "low", label: "Low" },
                { value: "medium", label: "Medium" },
                { value: "high", label: "High" },
                { value: "critical", label: "Critical" },
              ]}
            />
          </Form.Item>

          <Form.Item
            label="Description"
            name="description"
            rules={[{ required: true, message: "Please describe the issue" }]}
          >
            <Input.TextArea
              rows={4}
              placeholder="Provide steps to reproduce, logs, and expected behavior..."
            />
          </Form.Item>
        </Form>
      </Modal>

      {/* -------- Knowledge Base Drawer -------- */}
      <Drawer
        title="Knowledge Base Results"
        open={kbOpen}
        onClose={() => setKbOpen(false)}
        width={420}
        destroyOnClose
      >
        {kbError && (
          <Alert
            type="warning"
            showIcon
            message="Search warning"
            description={kbError}
            className="sp-drawer-alert"
          />
        )}

        {kbLoading ? (
          <div className="sp-muted">Searching...</div>
        ) : !kbResults.length ? (
          <div className="sp-empty">
            <Text type="secondary">No results found.</Text>
          </div>
        ) : (
          <List
            itemLayout="vertical"
            dataSource={kbResults}
            renderItem={(it) => (
              <List.Item className="sp-kb-item">
                <Space direction="vertical" size={2}>
                  <Text strong>{it?.title ?? "Article"}</Text>
                  <Text type="secondary" className="sp-muted">
                    {it?.snippet ?? ""}
                  </Text>
                  <Space size={6}>
                    {(it?.tags || []).map((t, i) => (
                      <Tag key={`${t}-${i}`}>{t}</Tag>
                    ))}
                  </Space>
                </Space>
              </List.Item>
            )}
          />
        )}
      </Drawer>

      {/* -------- Live Chat Drawer -------- */}
      <Drawer
        title="Live Chat"
        open={chatOpen}
        onClose={() => setChatOpen(false)}
        width={420}
        destroyOnClose
      >
        <Space direction="vertical" size={10} style={{ width: "100%" }}>
          <Alert
            type={hub.chat?.available ? "success" : "info"}
            showIcon
            message={hub.chat?.available ? "Agents are online" : "Chat is offline"}
            description={
              hub.chat?.available
                ? "You can start a conversation with our support team."
                : "This is a placeholder UI. Connect your Flask chat endpoint later."
            }
          />

          <Card bordered className="sp-chat-box">
            <div className="sp-chat-feed">
              <div className="sp-chat-bubble sp-chat-bubble--sys">
                This is a demo chat window.
              </div>
            </div>

            <Input
              placeholder="Type your message..."
              disabled={!hub.chat?.available}
              onPressEnter={() => message.info("Connect chat API to send messages.")}
            />
            <div className="sp-chat-actions">
              <Button
                type="primary"
                icon={<MessageOutlined />}
                disabled={!hub.chat?.available}
                onClick={() => message.info("Connect chat API to send messages.")}
              >
                Send
              </Button>
            </div>
          </Card>
        </Space>
      </Drawer>
    </div>
  );
}
