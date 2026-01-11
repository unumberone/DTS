import React, { useEffect, useMemo, useState } from "react";
import {
  Tabs,
  Card,
  Button,
  Tag,
  Modal,
  Form,
  Input,
  List,
  Space,
  Typography,
  Alert,
  message,
  Divider,
  Empty,
} from "antd";
import {
  KeyOutlined,
  ApiOutlined,
  CopyOutlined,
  LinkOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from "@ant-design/icons";
import "../css/setting.css";
import { getSettings, upsertApiKey, updateWebhooks } from "../api/settingsApi";

const { Title, Text } = Typography;

const TAB_ITEMS = [
  {
    key: "general",
    label: "General",
  },
  {
    key: "security",
    label: "Security",
  },
  {
    key: "integrations",
    label: "Integrations",
  },
];

export default function Settings() {
  const [activeTab, setActiveTab] = useState("integrations");

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const [settings, setSettings] = useState({
    apiKeys: [],
    webhooks: {
      enabled: false,
      endpoint: "",
      secret: "",
      events: [],
    },
  });

  // -------- Modals --------
  const [apiModalOpen, setApiModalOpen] = useState(false);
  const [webhookModalOpen, setWebhookModalOpen] = useState(false);

  // API Keys form state
  const [apiForm] = Form.useForm();
  const [apiSaveLoading, setApiSaveLoading] = useState(false);

  // Webhooks form state
  const [whForm] = Form.useForm();
  const [whSaveLoading, setWhSaveLoading] = useState(false);

  // load settings from backend
  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    setError("");

    getSettings({ signal: ac.signal })
      .then((json) => {
        setSettings({
          apiKeys: Array.isArray(json?.apiKeys) ? json.apiKeys : [],
          webhooks: json?.webhooks ?? {
            enabled: false,
            endpoint: "",
            secret: "",
            events: [],
          },
        });
      })
      .catch((e) => {
        if (e?.name !== "AbortError") {
          setError(e?.message || "Failed to load settings");
        }
      })
      .finally(() => setLoading(false));

    return () => ac.abort();
  }, []);

  // ---------- Handlers ----------
  const openApiKeys = () => {
    const first = settings.apiKeys?.[0];

    apiForm.setFieldsValue({
      keyName: first?.name || "",
      apiKeyValue: first?.valueMasked || "",
    });

    setApiModalOpen(true);
  };

  const openWebhooks = () => {
    const wh = settings.webhooks || {};
    whForm.setFieldsValue({
      enabled: !!wh.enabled,
      endpoint: wh.endpoint || "",
      secret: wh.secret || "",
      events: Array.isArray(wh.events) ? wh.events.join(", ") : "",
    });
    setWebhookModalOpen(true);
  };

  const handleCopyKey = async () => {
    const v = apiForm.getFieldValue("apiKeyValue");
    if (!v) {
      message.warning("No API key value to copy.");
      return;
    }

    try {
      await navigator.clipboard.writeText(String(v));
      message.success("Copied!");
    } catch {
      message.error("Copy failed. Please copy manually.");
    }
  };

  const handleSaveApiKeys = async () => {
    try {
      const values = await apiForm.validateFields();
      setApiSaveLoading(true);

      const payload = {
        name: values.keyName,
      };

      /**
       * Backend nên trả về:
       * {
       *   apiKeys: [{ id, name, status, valueMasked, createdAt }],
       *   generatedKeyValue?: "one-time-visible-secret"
       * }
       */
      const res = await upsertApiKey(payload);

      setSettings((prev) => ({
        ...prev,
        apiKeys: Array.isArray(res?.apiKeys) ? res.apiKeys : prev.apiKeys,
      }));

      // Nếu backend trả key mới 1 lần
      if (res?.generatedKeyValue) {
        apiForm.setFieldsValue({
          apiKeyValue: res.generatedKeyValue,
        });
      } else {
        // fallback hiển thị masked theo list mới nếu có
        const first = res?.apiKeys?.[0];
        if (first?.valueMasked) {
          apiForm.setFieldsValue({ apiKeyValue: first.valueMasked });
        }
      }

      message.success("Settings saved successfully!");
      setApiModalOpen(false);
    } catch (e) {
      if (e?.errorFields) return;
      message.error(e?.message || "Save failed");
    } finally {
      setApiSaveLoading(false);
    }
  };

  const handleSaveWebhooks = async () => {
    try {
      const values = await whForm.validateFields();
      setWhSaveLoading(true);

      const payload = {
        enabled: !!values.enabled,
        endpoint: values.endpoint?.trim() || "",
        secret: values.secret?.trim() || "",
        events: String(values.events || "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      };

      const res = await updateWebhooks(payload);

      setSettings((prev) => ({
        ...prev,
        webhooks: res?.webhooks ?? payload,
      }));

      message.success("Settings saved successfully!");
      setWebhookModalOpen(false);
    } catch (e) {
      if (e?.errorFields) return;
      message.error(e?.message || "Save failed");
    } finally {
      setWhSaveLoading(false);
    }
  };

  // Optional: nút save tổng 
  const handleSaveAll = async () => {
    setSaving(true);
    try {

      message.success("Settings saved successfully!");
    } finally {
      setSaving(false);
    }
  };

  const apiKeysList = useMemo(() => settings.apiKeys || [], [settings.apiKeys]);

  return (
    <div className="cg-settings">
      <div className="cg-settings__head">
        <div>
          <Title level={4} className="cg-settings__title">
            Settings
          </Title>
          <Text className="cg-settings__subtitle">
            Manage your application and security preferences
          </Text>
        </div>

        <Button
          type="primary"
          icon={<SettingOutlined />}
          loading={saving}
          onClick={handleSaveAll}
          className="cg-settings__save"
        >
          Save Changes
        </Button>
      </div>

      {error && (
        <Alert
          type="warning"
          showIcon
          message="Settings API warning"
          description={error}
          className="cg-settings__error"
        />
      )}

      <Card className="cg-settings__card" bordered={false}>
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          items={TAB_ITEMS.map((t) => ({
            key: t.key,
            label: t.label,
            children: (
              <TabBody
                tabKey={t.key}
                loading={loading}
                settings={settings}
                onOpenApiKeys={openApiKeys}
                onOpenWebhooks={openWebhooks}
              />
            ),
          }))}
        />
      </Card>

      {/* -------- API Keys Modal -------- */}
      <Modal
        open={apiModalOpen}
        onCancel={() => setApiModalOpen(false)}
        title="Configure API Keys"
        okText="Save"
        cancelText="Cancel"
        onOk={handleSaveApiKeys}
        confirmLoading={apiSaveLoading}
        destroyOnClose
        className="cg-settings__modal"
      >
        <Form
          form={apiForm}
          layout="vertical"
          requiredMark={false}
          initialValues={{ keyName: "", apiKeyValue: "" }}
        >
          <Form.Item
            label="Key Name"
            name="keyName"
            rules={[
              { required: true, message: "Please enter key name" },
              { max: 80, message: "Key name is too long" },
            ]}
          >
            <Input placeholder="Default Key" />
          </Form.Item>

          <Form.Item label="API Key Value" name="apiKeyValue">
            <Input.Password
              placeholder="****************"
              readOnly
              addonAfter={
                <Button
                  type="text"
                  icon={<CopyOutlined />}
                  onClick={handleCopyKey}
                >
                  Copy
                </Button>
              }
            />
          </Form.Item>

          <Divider className="cg-settings__divider" />

          <Text strong>Active Keys</Text>

          <div className="cg-settings__active-keys">
            {!apiKeysList.length ? (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="No active keys"
              />
            ) : (
              <List
                size="small"
                dataSource={apiKeysList}
                renderItem={(k) => (
                  <List.Item>
                    <Space direction="vertical" size={0}>
                      <Text>
                        {k?.name || "Key"}{" "}
                        <Text type="success">
                          {k?.status ? `(${k.status})` : "(Active)"}
                        </Text>{" "}
                        - {k?.valueMasked || "[********]"}
                      </Text>
                      <Text type="secondary" className="cg-settings__muted">
                        Created on {k?.createdAt || "--"}
                      </Text>
                    </Space>
                  </List.Item>
                )}
              />
            )}
          </div>
        </Form>
      </Modal>

      {/* -------- Webhooks Modal -------- */}
      <Modal
        open={webhookModalOpen}
        onCancel={() => setWebhookModalOpen(false)}
        title="Configure Webhooks"
        okText="Save"
        cancelText="Cancel"
        onOk={handleSaveWebhooks}
        confirmLoading={whSaveLoading}
        destroyOnClose
        className="cg-settings__modal"
      >
        <Form
          form={whForm}
          layout="vertical"
          requiredMark={false}
          initialValues={{
            enabled: false,
            endpoint: "",
            secret: "",
            events: "",
          }}
        >
          <Form.Item name="enabled" label="Enable Webhooks" valuePropName="checked">
            {/* dùng checkbox style input đơn giản để không kéo thêm Switch logic */}
            <Input type="checkbox" className="cg-settings__checkbox" />
          </Form.Item>

          <Form.Item
            label="Endpoint URL"
            name="endpoint"
            rules={[
              { required: true, message: "Please enter endpoint URL" },
            ]}
          >
            <Input placeholder="https://your-service/webhooks/cyberguard" />
          </Form.Item>

          <Form.Item label="Signing Secret" name="secret">
            <Input.Password placeholder="Optional secret for signature verification" />
          </Form.Item>

          <Form.Item
            label="Events (comma separated)"
            name="events"
          >
            <Input placeholder="scan.completed, threat.detected, report.exported" />
          </Form.Item>

          <Text type="secondary" className="cg-settings__muted">
            Configure real-time event notifications for system activities.
          </Text>
        </Form>
      </Modal>
    </div>
  );
}

function TabBody({ tabKey, loading, settings, onOpenApiKeys, onOpenWebhooks }) {
  if (loading) {
    return (
      <div className="cg-settings__loading">
        <Card bordered={false} className="cg-settings__skeleton" />
        <Card bordered={false} className="cg-settings__skeleton" />
      </div>
    );
  }

  if (tabKey === "integrations") {
    return (
      <div className="cg-settings__grid">
        {/* API KEYS */}
        <Card
          bordered
          className="cg-int-card"
          title={
            <Space>
              <KeyOutlined />
              <span>API Keys</span>
              <Tag color="gold" className="cg-int-card__tag">
                Sensitive Data
              </Tag>
            </Space>
          }
          extra={
            <Button onClick={onOpenApiKeys}>
              Configure
            </Button>
          }
        >
          <Text className="cg-int-card__desc">
            Manage your API keys for programmatic access. Treat them like
            passwords.
          </Text>

          <div className="cg-int-card__meta">
            <Text type="secondary">
              Active keys: {Array.isArray(settings?.apiKeys) ? settings.apiKeys.length : 0}
            </Text>
          </div>
        </Card>

        {/* WEBHOOKS */}
        <Card
          bordered
          className="cg-int-card"
          title={
            <Space>
              <ApiOutlined />
              <span>Webhooks</span>
            </Space>
          }
          extra={
            <Button onClick={onOpenWebhooks}>
              Configure
            </Button>
          }
        >
          <Text className="cg-int-card__desc">
            Configure real-time event notifications for system activities.
          </Text>

          <div className="cg-int-card__meta">
            <Text type="secondary">
              Status: {settings?.webhooks?.enabled ? "Enabled" : "Disabled"}
            </Text>
          </div>
        </Card>
      </div>
    );
  }

  if (tabKey === "general") {
    return (
      <Card bordered className="cg-int-card">
        <Space>
          <SettingOutlined />
          <Text strong>General</Text>
        </Space>
        <div className="cg-placeholder">
          <Text type="secondary">
            Add your general settings here (branding, locale, UI preferences).
          </Text>
        </div>
      </Card>
    );
  }

  // security
  return (
    <Card bordered className="cg-int-card">
      <Space>
        <SafetyCertificateOutlined />
        <Text strong>Security</Text>
      </Space>
      <div className="cg-placeholder">
        <Text type="secondary">
          Add your security settings here (MFA, session timeout, password policy).
        </Text>
      </div>
    </Card>
  );
}
