# Admin UI Overhaul Plan

## Current State

The admin-ui at `admin-ui/server.js` is a leftover from single-server OpenClaw. It manages local OpenClaw agents/workspaces, not OCMT multi-tenant users/containers.

**Current routes:**
- `/` - Old signup page (public) - creates local workspaces
- `/signup` - Creates workspace (public)
- `/connect` - Integration options (public)
- `/chat` - Web chat (public)
- `/admin` - View agents, approve pairings (protected - header auth)
- `/dev` - Config viewer (protected)
- `/dev/browse` - File browser (protected)

**Access:** Binds to `127.0.0.1` by default - only accessible via SSH tunnel. Not public.

**Auth:** Requires `ADMIN_TOKEN` in `Authorization: Bearer <token>` header.

---

## Implemented Backend APIs

The following API endpoints have been implemented in `management-server` and need UI:

### User Allowlist API (`/api/admin/user-allowlist`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/user-allowlist` | GET | List entries and settings |
| `/api/admin/user-allowlist` | POST | Add email/domain entry |
| `/api/admin/user-allowlist/:id` | DELETE | Remove entry |
| `/api/admin/user-allowlist/:id/enable` | POST | Enable entry |
| `/api/admin/user-allowlist/:id/disable` | POST | Disable entry |
| `/api/admin/user-allowlist/toggle` | POST | Toggle feature on/off |
| `/api/admin/user-allowlist/pending-users` | GET | List users pending approval |
| `/api/admin/user-allowlist/approve/:userId` | POST | Approve pending user |
| `/api/admin/user-allowlist/reject/:userId` | POST | Reject and delete pending user |
| `/api/admin/user-allowlist/check` | POST | Test if email would be allowed |

### Database Tables

```sql
-- Allowlist entries (emails and domains)
user_allowlist (
  id UUID PRIMARY KEY,
  entry_type VARCHAR(20) CHECK (entry_type IN ('email', 'domain')),
  value VARCHAR(255),
  description TEXT,
  created_by UUID,
  created_at TIMESTAMP,
  expires_at TIMESTAMP,
  enabled BOOLEAN DEFAULT true
)

-- Feature settings
user_allowlist_settings (
  key VARCHAR(100) PRIMARY KEY,
  value JSONB,
  updated_by UUID,
  updated_at TIMESTAMP
)
```

### Allowlist Behavior

- **Empty + Disabled** (default): Allow all users (backward compatible)
- **Empty + Enabled**: Block all new users (require manual approval)
- **Has entries + Enabled**: Auto-approve matching emails/domains, block others

---

## Phase 1: Session-Based Login

**Goal:** Allow browser access without ModHeader extension.

### Changes to `admin-ui/server.js`:

1. Add `/login` GET route - render login form
2. Add `/login` POST route - validate token, set session cookie
3. Add `/logout` route - clear session
4. Modify `requireAuth` middleware to accept:
   - `Authorization: Bearer <token>` header (existing)
   - OR `admin_session` cookie (new)

### Implementation:

```javascript
import cookieParser from 'cookie-parser';

app.use(cookieParser());

// Session storage (in production, use Redis or similar)
const validSessions = new Map();

// Session secret for signing cookies
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Login page
app.get('/login', (req, res) => {
  res.send(`<!DOCTYPE html>...login form...`);
});

// Login handler
app.post('/login', (req, res) => {
  const { token } = req.body;
  if (token === ADMIN_TOKEN) {
    // Set signed session cookie
    const sessionToken = crypto.randomBytes(32).toString('hex');
    validSessions.set(sessionToken, { createdAt: Date.now() });
    res.cookie('admin_session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    res.redirect('/admin');
  } else {
    res.redirect('/login?error=1');
  }
});

// Update requireAuth to check cookie too
function requireAuth(req, res, next) {
  // Check header first
  const headerToken = req.headers.authorization?.replace('Bearer ', '');
  if (headerToken && timingSafeEqual(headerToken, ADMIN_TOKEN)) {
    return next();
  }

  // Check session cookie
  const sessionCookie = req.cookies?.admin_session;
  if (sessionCookie && validSessions.has(sessionCookie)) {
    return next();
  }

  // Redirect to login for browser requests, 401 for API
  if (req.accepts('html')) {
    return res.redirect('/login');
  }
  return res.status(401).json({ error: 'Unauthorized' });
}
```

---

## Phase 2: Remove Old Pages

**Goal:** Clean up unused single-user OpenClaw flows.

### Remove or gate:
- `/` → Redirect to `/login` or `/admin`
- `/signup` → Remove (OCMT users signup via user-ui, not admin-ui)
- `/connect` → Remove
- `/chat` → Remove

### Keep:
- `/admin` - Main dashboard (to be redesigned)
- `/dev` - Config viewer (useful for debugging)
- `/dev/browse` - File browser (useful for debugging)
- `/login` - New login page
- `/logout` - New logout

---

## Phase 3: OCMT Admin Features

Replace old agent management with OCMT user/container management.

### New `/admin` Dashboard Sections:

#### 3.1 Overview Stats
- Total users
- Active users (with containers)
- Pending approval users
- Running containers

#### 3.2 User Allowlist Management
- Toggle: Enable/disable allowlist feature
- Add entry form (email or domain)
- List of entries with enable/disable/delete actions
- Test email input to check if it would be allowed

#### 3.3 Pending Users Queue
- List users with `status = 'pending_approval'`
- Approve button (changes status to 'pending', user gets container on next login)
- Reject button (deletes user account)

#### 3.4 User Management
- List all users from PostgreSQL
- Show status, email, container info
- Link to user details

#### 3.5 Container Status
- List containers via agent-server API
- Show hibernation state, memory, last activity
- Actions: wake, hibernate, restart

### New Routes:

```
GET  /admin                    - Dashboard overview
GET  /admin/allowlist          - Allowlist management page
GET  /admin/pending            - Pending users page
GET  /admin/users              - User list page
GET  /admin/users/:id          - User detail page
GET  /admin/containers         - Container list page
```

### API Proxy Pattern:

Admin-ui will proxy requests to management-server:

```javascript
const MANAGEMENT_SERVER_URL = process.env.MANAGEMENT_SERVER_URL || 'http://localhost:3000';
const MANAGEMENT_API_TOKEN = process.env.MANAGEMENT_API_TOKEN;

async function proxyToManagement(path, options = {}) {
  const response = await fetch(`${MANAGEMENT_SERVER_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${MANAGEMENT_API_TOKEN}`,
      ...options.headers,
    },
  });
  return response.json();
}

// Example: List allowlist entries
app.get('/api/allowlist', requireAuth, async (req, res) => {
  const data = await proxyToManagement('/api/admin/user-allowlist');
  res.json(data);
});
```

---

## Phase 4: Modern UI (Optional)

Consider migrating to a proper frontend framework:

- **Option A:** Keep server-rendered HTML (current approach, simple)
- **Option B:** Add Lit components (matches user-ui)
- **Option C:** Build separate SPA (React/Vue)

For now, Phase 3 will use server-rendered HTML with modern CSS.

---

## Files to Modify

| File | Changes |
|------|---------|
| `admin-ui/server.js` | Add login/logout, update requireAuth, remove old routes, add OCMT admin routes |
| `admin-ui/package.json` | Add `cookie-parser` dependency |
| `admin-ui/.env.example` | Add `SESSION_SECRET`, `MANAGEMENT_SERVER_URL`, `MANAGEMENT_API_TOKEN` |

---

## Testing

### Phase 1: Login
1. Start admin-ui with `ADMIN_TOKEN` set
2. Visit `http://localhost:3000/login`
3. Enter token, submit
4. Should redirect to `/admin` with session cookie
5. Refresh - should stay logged in
6. Visit `/logout` - should redirect to `/login`

### Phase 3: OCMT Features
1. Enable allowlist, verify new users get `pending_approval` status
2. Add domain "example.com", verify matching emails auto-approve
3. Approve a pending user, verify they can login
4. View container list, verify status matches Docker

---

## Dependencies

- Management-server must be running and accessible
- Agent-server must be running for container status
- Database must have the new `user_allowlist` and `user_allowlist_settings` tables

---

## Security Considerations

1. **Admin-ui should never be exposed publicly** - keep `ADMIN_BIND=127.0.0.1`
2. **Management API token** - use a strong, unique token for admin-ui to management-server communication
3. **Session expiry** - sessions should expire after 24 hours
4. **Audit logging** - all admin actions are logged via management-server's audit system

---

## Future Enhancements

### Integrate Admin into User-UI (Recommended)

Currently admin-ui requires SSH tunnel access (`ADMIN_BIND=127.0.0.1`). For easier multi-admin access, consider integrating admin features into user-ui:

**Approach:**
1. Add `role` field to users table (`user`, `admin`, `super_admin`)
2. Add role check middleware to user-ui
3. Add `/admin/*` routes to user-ui, gated by admin role
4. Reuse existing management-server proxy pattern
5. Share styling with existing user-ui components (Lit)

**Benefits:**
- Single app to deploy and maintain
- Existing authentication (magic link + session)
- Consistent UI/UX with user-facing pages
- No SSH tunnel required for admins
- Role-based access control

**Alternative approaches:**
- Expose admin-ui behind VPN/Tailscale (`ADMIN_BIND=0.0.0.0` on private network)
- Keep SSH tunnel for single-admin deployments (current approach)
