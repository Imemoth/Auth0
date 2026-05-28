import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ApiCallError, type ApiCallMeta, callApi, pretty } from './api';
import './styles.css';

type FormState = {
  registerEmail: string;
  registerPassword: string;
  verifyToken: string;
  loginEmail: string;
  loginPassword: string;
  mfaChallengeToken: string;
  mfaCode: string;
  setupTotpCode: string;
  accessToken: string;
  refreshToken: string;
};

type Feedback = {
  kind: 'idle' | 'running' | 'success' | 'error';
  title: string;
  detail: string;
};

const initialForm: FormState = {
  registerEmail: 'demo@example.com',
  registerPassword: 'VeryStrongPassword123!',
  verifyToken: '',
  loginEmail: 'demo@example.com',
  loginPassword: 'VeryStrongPassword123!',
  mfaChallengeToken: '',
  mfaCode: '',
  setupTotpCode: '',
  accessToken: '',
  refreshToken: ''
};

function App() {
  const [form, setForm] = useState<FormState>(initialForm);
  const [output, setOutput] = useState('Ready.');
  const [loading, setLoading] = useState<string | null>(null);
  const [totp, setTotp] = useState<{ secret?: string; otpauthUrl?: string; note?: string } | null>(null);
  const [logs, setLogs] = useState<ApiCallMeta[]>([]);
  const [feedback, setFeedback] = useState<Feedback>({
    kind: 'idle',
    title: 'Ready',
    detail: 'A mock console készen áll. Indíts egy Health checket vagy Register flow-t.'
  });

  const isAuthenticated = useMemo(() => Boolean(form.accessToken), [form.accessToken]);
  const latestLog = logs[0];

  function patch(update: Partial<FormState>) {
    setForm((current) => ({ ...current, ...update }));
  }

  function pushLog(meta: ApiCallMeta) {
    setLogs((current) => [meta, ...current].slice(0, 80));
  }

  async function run(label: string, action: () => Promise<{ data: unknown; meta: ApiCallMeta }>) {
    setLoading(label);
    setFeedback({ kind: 'running', title: `Running: ${label}`, detail: 'API hívás folyamatban...' });
    try {
      const { data, meta } = await action();
      pushLog(meta);
      setOutput(pretty(data));
      setFeedback({
        kind: 'success',
        title: `${meta.method} ${meta.path} -> ${meta.status}`,
        detail: `Sikeres hívás ${meta.durationMs} ms alatt.`
      });
      return data as any;
    } catch (error) {
      if (error instanceof ApiCallError) {
        pushLog(error.meta);
        setOutput(pretty(error.meta.errorBody));
        setFeedback({
          kind: 'error',
          title: `${error.meta.method} ${error.meta.path} -> ${error.meta.status || 'ERR'}`,
          detail: `Sikertelen hívás ${error.meta.durationMs} ms alatt.`
        });
      } else {
        setOutput(pretty(error));
        setFeedback({ kind: 'error', title: 'Unexpected UI error', detail: error instanceof Error ? error.message : 'Unknown error' });
      }
      return null;
    } finally {
      setLoading(null);
    }
  }

  function applyTokens(result: any) {
    if (result?.accessToken || result?.refreshToken || result?.sessionId) {
      patch({
        accessToken: result.accessToken ?? form.accessToken,
        refreshToken: result.refreshToken ?? form.refreshToken
      });
    }
    if (result?.challengeToken) {
      patch({ mfaChallengeToken: result.challengeToken });
    }
  }

  async function registerUser() {
    const result = await run('register', () => callApi('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email: form.registerEmail, password: form.registerPassword })
    }));
    if (result?.devEmailVerificationToken) patch({ verifyToken: result.devEmailVerificationToken });
  }

  async function verifyEmail() {
    await run('verify-email', () => callApi('/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify({ token: form.verifyToken })
    }));
  }

  async function login() {
    const result = await run('login', () => callApi('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: form.loginEmail, password: form.loginPassword, deviceFingerprint: 'mock-react-console' })
    }));
    applyTokens(result);
  }

  async function completeMfa() {
    const result = await run('complete-mfa', () => callApi('/auth/mfa/complete', {
      method: 'POST',
      body: JSON.stringify({ challengeToken: form.mfaChallengeToken, code: form.mfaCode })
    }));
    applyTokens(result);
  }

  async function refresh() {
    const result = await run('refresh-token', () => callApi('/auth/token/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: form.refreshToken })
    }));
    applyTokens(result);
  }

  async function logout() {
    await run('logout', () => callApi('/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: form.refreshToken })
    }, form.accessToken));
    patch({ accessToken: '', refreshToken: '' });
  }

  async function me() {
    await run('me', () => callApi('/me', { method: 'GET' }, form.accessToken));
  }

  async function sessions() {
    await run('sessions', () => callApi('/auth/sessions', { method: 'GET' }, form.accessToken));
  }

  async function audit() {
    await run('audit', () => callApi('/admin/audit-events', { method: 'GET' }));
  }

  async function health() {
    await run('health', () => callApi('/health', { method: 'GET' }));
  }

  async function startTotpSetup() {
    const result = await run('start-totp-setup', () => callApi('/auth/mfa/totp/setup', {
      method: 'POST',
      body: JSON.stringify({})
    }, form.accessToken));
    if (result) setTotp(result);
  }

  async function verifyTotpSetup() {
    await run('verify-totp-setup', () => callApi('/auth/mfa/totp/verify-setup', {
      method: 'POST',
      body: JSON.stringify({ code: form.setupTotpCode })
    }, form.accessToken));
  }

  async function copyText(value: string, label: string) {
    await navigator.clipboard.writeText(value);
    setFeedback({ kind: 'success', title: `${label} copied`, detail: 'Vágólapra másolva.' });
  }

  return (
    <div className="shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Identity Management Mock</p>
          <h1>Auth0-style Identity Console</h1>
          <p className="subtitle">React + Vite tesztfelület visszajelzésekkel és kliensoldali API loggal.</p>
        </div>
        <div className={isAuthenticated ? 'status ok' : 'status'}>{isAuthenticated ? 'Authenticated' : 'Anonymous'}</div>
      </header>

      <section className={`feedback ${feedback.kind}`}>
        <div>
          <strong>{feedback.title}</strong>
          <span>{feedback.detail}</span>
        </div>
        {latestLog && <code>{latestLog.method} {latestLog.path} | {latestLog.status || 'ERR'} | {latestLog.durationMs}ms</code>}
      </section>

      <main className="grid">
        <Card title="1. Register">
          <Input label="Email" value={form.registerEmail} onChange={(value) => patch({ registerEmail: value })} />
          <Input label="Password" type="password" value={form.registerPassword} onChange={(value) => patch({ registerPassword: value })} />
          <Button busy={loading === 'register'} onClick={registerUser}>Register</Button>
        </Card>

        <Card title="2. Verify email">
          <Input label="Verification token" value={form.verifyToken} onChange={(value) => patch({ verifyToken: value })} />
          <Button busy={loading === 'verify-email'} onClick={verifyEmail}>Verify email</Button>
        </Card>

        <Card title="3. Login">
          <Input label="Email" value={form.loginEmail} onChange={(value) => patch({ loginEmail: value })} />
          <Input label="Password" type="password" value={form.loginPassword} onChange={(value) => patch({ loginPassword: value })} />
          <Button busy={loading === 'login'} onClick={login}>Login</Button>
        </Card>

        <Card title="4. MFA challenge">
          <Input label="Challenge token" value={form.mfaChallengeToken} onChange={(value) => patch({ mfaChallengeToken: value })} />
          <Input label="TOTP code" value={form.mfaCode} onChange={(value) => patch({ mfaCode: value })} />
          <Button busy={loading === 'complete-mfa'} onClick={completeMfa}>Complete MFA</Button>
        </Card>

        <Card title="5. TOTP setup">
          <Button busy={loading === 'start-totp-setup'} onClick={startTotpSetup}>Start TOTP setup</Button>
          {totp && <div className="totpBox"><strong>Secret</strong><code>{totp.secret}</code><button onClick={() => copyText(totp.secret ?? '', 'TOTP secret')}>Copy secret</button><strong>otpauth URL</strong><textarea readOnly value={totp.otpauthUrl ?? ''} rows={4} /><small>{totp.note}</small></div>}
          <Input label="Setup TOTP code" value={form.setupTotpCode} onChange={(value) => patch({ setupTotpCode: value })} />
          <Button busy={loading === 'verify-totp-setup'} onClick={verifyTotpSetup}>Verify setup</Button>
        </Card>

        <Card title="6. Session & diagnostics">
          <div className="buttonGrid">
            <Button busy={loading === 'health'} onClick={health}>Health</Button>
            <Button busy={loading === 'me'} onClick={me}>GET /me</Button>
            <Button busy={loading === 'sessions'} onClick={sessions}>Sessions</Button>
            <Button busy={loading === 'refresh-token'} onClick={refresh}>Refresh</Button>
            <Button busy={loading === 'audit'} onClick={audit}>Audit</Button>
            <Button variant="danger" busy={loading === 'logout'} onClick={logout}>Logout</Button>
          </div>
          <Textarea label="Access token" value={form.accessToken} onChange={(value) => patch({ accessToken: value })} rows={4} />
          <Button onClick={() => copyText(form.accessToken, 'Access token')}>Copy access token</Button>
          <Textarea label="Refresh token" value={form.refreshToken} onChange={(value) => patch({ refreshToken: value })} rows={3} />
          <Button onClick={() => copyText(form.refreshToken, 'Refresh token')}>Copy refresh token</Button>
        </Card>

        <section className="responsePanel">
          <div className="responseHeader"><h2>Response</h2><div className="responseActions"><button onClick={() => copyText(output, 'Response')}>Copy response</button>{loading && <span>Running: {loading}</span>}</div></div>
          <pre>{output}</pre>
        </section>

        <section className="logPanel">
          <div className="responseHeader"><h2>Client request log</h2><div className="responseActions"><button onClick={() => setLogs([])}>Clear logs</button><span>{logs.length} entries</span></div></div>
          <div className="logList">
            {logs.length === 0 && <p className="empty">Nincs még API hívás.</p>}
            {logs.map((log) => <LogItem key={log.id} log={log} />)}
          </div>
        </section>
      </main>
    </div>
  );
}

function LogItem({ log }: { log: ApiCallMeta }) {
  return <details className={log.ok ? 'logItem ok' : 'logItem error'}><summary><span className="badge">{log.ok ? 'OK' : 'ERR'}</span><strong>{log.method} {log.path}</strong><em>{log.status || 'network'} / {log.durationMs}ms</em><time>{new Date(log.startedAt).toLocaleTimeString()}</time></summary><pre>{pretty({ request: log.requestBody, response: log.responseBody, error: log.errorBody })}</pre></details>;
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="card"><h2>{title}</h2>{children}</section>;
}

function Input({ label, value, onChange, type = 'text' }: { label: string; value: string; onChange: (value: string) => void; type?: string }) {
  return <label className="field"><span>{label}</span><input type={type} value={value} onChange={(event) => onChange(event.target.value)} /></label>;
}

function Textarea({ label, value, onChange, rows }: { label: string; value: string; onChange: (value: string) => void; rows: number }) {
  return <label className="field"><span>{label}</span><textarea value={value} rows={rows} onChange={(event) => onChange(event.target.value)} /></label>;
}

function Button({ children, onClick, busy, variant = 'primary' }: { children: React.ReactNode; onClick: () => void; busy?: boolean; variant?: 'primary' | 'danger' }) {
  return <button className={variant} disabled={busy} onClick={onClick}>{busy ? 'Working...' : children}</button>;
}

createRoot(document.getElementById('root')!).render(<App />);
