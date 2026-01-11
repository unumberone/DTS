import React, { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import TEST_ACCOUNTS from "../test/test_acc.js";
import "../css/login.css";

const STORAGE_KEY = "cg_user";
const REDIRECT_DELAY = 250;

function readStoredUser() {
  try {
    const ls = localStorage.getItem(STORAGE_KEY);
    if (ls) return JSON.parse(ls);
    const ss = sessionStorage.getItem(STORAGE_KEY);
    if (ss) return JSON.parse(ss);
  } catch (_) {}
  return null;
}

function writeStoredUser(payload, remember) {
  try {
    localStorage.removeItem(STORAGE_KEY);
    sessionStorage.removeItem(STORAGE_KEY);

    const data = JSON.stringify(payload);
    if (remember) localStorage.setItem(STORAGE_KEY, data);
    else sessionStorage.setItem(STORAGE_KEY, data);
  } catch (_) {}
}

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [remember, setRemember] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const normalizedEmail = useMemo(() => email.trim().toLowerCase(), [email]);
  const normalizedPassword = useMemo(() => password.trim(), [password]);

  useEffect(() => {
    const user = readStoredUser();
    if (user) navigate("/overview", { replace: true });
  }, [navigate]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (submitting) return;

    setError("");
    setSuccess("");

    if (!normalizedEmail || !normalizedPassword) {
      setError("Vui lòng nhập email và mật khẩu.");
      return;
    }

    setSubmitting(true);

    const user = TEST_ACCOUNTS.find(
      (acc) =>
        acc.email?.toLowerCase() === normalizedEmail &&
        acc.password === normalizedPassword
    );

    if (!user) {
      setSubmitting(false);
      setError("Invalid email or password.");
      return;
    }

    const dataToStore = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      loginAt: new Date().toISOString(),
    };

    writeStoredUser(dataToStore, remember);

    setSuccess(`Đăng nhập thành công, xin chào ${user.name}`);
    setSubmitting(false);

    const to =
      location.state?.from?.pathname ||
      location.state?.from ||
      "/overview";

    window.setTimeout(() => {
      navigate(to, { replace: true });
    }, REDIRECT_DELAY);
  };

  const wrapClass = `cg-input ${error ? "cg-input--error" : ""}`;

  return (
    <div className="cg-login">
      <div className="cg-login__grid">
        <section className="cg-left">
          <div className="cg-left__glow cg-left__glow--a" />
          <div className="cg-left__glow cg-left__glow--b" />

          <div className="cg-left__content">
            <div className="cg-left__brand">
              <span className="cg-left__badge">
                <ShieldIcon className="cg-icon cg-icon--brand" />
              </span>
              <span className="cg-left__brand-text">CyberGuard Platform</span>
            </div>

            <h1 className="cg-left__title">
              Ransomware Analysis <br /> &amp; Detection
            </h1>
            <p className="cg-left__subtitle">
              Detect ransomware in real time using deep learning.
            </p>

            <div className="cg-left__mock" />
          </div>
        </section>

        <section className="cg-right">
          <div className="cg-right__wrap">
            <div className="cg-card">
              <h2 className="cg-card__title">Sign in to your account</h2>

              {success && (
                <div className="cg-banner cg-banner--success">
                  {success}
                </div>
              )}

              {error && (
                <div className="cg-banner cg-banner--error">
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit} className="cg-form">
                <div className="cg-field">
                  <label className="cg-label">Email</label>
                  <div className={wrapClass}>
                    <MailIcon className="cg-icon cg-icon--muted" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value);
                        if (error) setError("");
                      }}
                      placeholder="Enter your email address"
                      className="cg-input__control"
                      autoComplete="email"
                    />
                  </div>
                </div>

                <div className="cg-field">
                  <label className="cg-label">Password</label>
                  <div className={wrapClass}>
                    <LockIcon className="cg-icon cg-icon--muted" />
                    <input
                      type={showPw ? "text" : "password"}
                      value={password}
                      onChange={(e) => {
                        setPassword(e.target.value);
                        if (error) setError("");
                      }}
                      placeholder="Enter your password"
                      className="cg-input__control"
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPw((s) => !s)}
                      className="cg-showpw"
                    >
                      {showPw ? "Hide" : "Show"}
                    </button>
                  </div>

                  {error && (
                    <p className="cg-help cg-help--error">
                      invalid email or password.
                    </p>
                  )}
                </div>

                <div className="cg-row">
                  <label className="cg-remember">
                    <input
                      type="checkbox"
                      checked={remember}
                      onChange={(e) => setRemember(e.target.checked)}
                    />
                    <span>Remember me</span>
                  </label>

                  <a className="cg-link" href="#">
                    Forgot password?
                  </a>
                </div>

                <button
                  type="submit"
                  className="cg-btn"
                  disabled={submitting}
                  aria-busy={submitting}
                >
                  {submitting ? "Signing in..." : "Sign in"}
                </button>

                <p className="cg-note">
                  Secure access for authorized analysts and administrators only.
                </p>
              </form>
            </div>

            <div className="cg-hint">
              <div className="cg-hint__title">Test accounts (demo):</div>
              <ul className="cg-hint__list">
                {TEST_ACCOUNTS.slice(0, 3).map((u) => (
                  <li key={u.id}>
                    • {u.email} / {u.password}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function ShieldIcon({ className = "" }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 3 20 6v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3Z" />
      <path d="M9.5 12.2 11 13.7l3.8-3.8" />
    </svg>
  );
}

function MailIcon({ className = "" }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="m3 7 9 6 9-6" />
    </svg>
  );
}

function LockIcon({ className = "" }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="4" y="11" width="16" height="9" rx="2" />
      <path d="M8 11V8a4 4 0 1 1 8 0v3" />
      <path d="M12 15v2" />
    </svg>
  );
}
