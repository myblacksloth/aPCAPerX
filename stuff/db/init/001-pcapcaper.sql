-- PCAPCaper PostgreSQL initialization.
--
-- The Docker postgres image creates the database named by POSTGRES_DB before
-- running this file. This script owns the application schema and the baseline
-- demo account; the backend must only read/write these tables.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    totp_secret TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    username TEXT,
    challenge TEXT NOT NULL,
    purpose TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_passkeys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_user_id ON user_recovery_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_id ON webauthn_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_user_passkeys_user_id ON user_passkeys(user_id);

-- Demo user:
--   username: demo
--   password: demo
-- password_hash is a Unix-style SHA-512 crypt hash generated with:
--   openssl passwd -6 -salt pcapcaperseed demo
INSERT INTO users (id, username, password_hash, display_name)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'demo',
    '$6$pcapcaperseed$x5qu696yeos70y/R3XrI3.gFfgPOToUtklyg4eArf2rXE5I8t2xO/IK2Gkz/GXIJIwRL5my6U2UV0iEtPoUND1',
    'Demo'
)
ON CONFLICT (username) DO NOTHING;

-- Demo recovery codes are visible in the profile page by requirement.
-- Each row also stores a Unix-style SHA-512 crypt hash used for verification.
INSERT INTO user_recovery_codes (id, user_id, code, code_hash)
VALUES
    ('00000000-0000-0000-0001-000000000001', '00000000-0000-0000-0000-000000000001', 'demo-0001-demo', '$6$pcapcaperseed$SLMj8.waO09RBHK5O5JtQ1BmpVdKkPTZAOrR.oL5wza1jSOsT4IvCPs1LYiAcqK0GmP3g2J18ppUkv8adpx1t0'),
    ('00000000-0000-0000-0001-000000000002', '00000000-0000-0000-0000-000000000001', 'demo-0002-demo', '$6$pcapcaperseed$XrqLzjWV/6.cnDNtTn3YxYHicsjdHEaSfv23MisPkifsPugueDaXCHtc.tyh0.zksFhxzraK8JTlJouceSg7G1'),
    ('00000000-0000-0000-0001-000000000003', '00000000-0000-0000-0000-000000000001', 'demo-0003-demo', '$6$pcapcaperseed$ARFWDPOw5KXj2XdzA/1nqdkUBoCoEhmbc2KbZTWHPgFwrsnrypmwGvpAYJSZOeLqBerbgNBNKVFvO6wiPYfJb/'),
    ('00000000-0000-0000-0001-000000000004', '00000000-0000-0000-0000-000000000001', 'demo-0004-demo', '$6$pcapcaperseed$p32y2ovZwZ.gssJ4srRO9zeFI0n7NE8Vg1tQwapMzOqZsXjj25f8x5uX.Dw5YbJa5LWUE3mOAcNdGKS9BhrNx1'),
    ('00000000-0000-0000-0001-000000000005', '00000000-0000-0000-0000-000000000001', 'demo-0005-demo', '$6$pcapcaperseed$rU7J5VpKKQMjpge.r7VZbB.xhlLXOkDfwovGigjk/k1t2.iTLzFIGDOA7FmKk/yLolOU2QBwmHZdyQUeQFvuE0'),
    ('00000000-0000-0000-0001-000000000006', '00000000-0000-0000-0000-000000000001', 'demo-0006-demo', '$6$pcapcaperseed$2XxhJYN63Qbwx3OOUnxXid8WNWy4BTPmlh7yLJYIv.BQCbUqNI54gpC.gmT3/qCEbytcshZbZfEMfaC3v59fy1'),
    ('00000000-0000-0000-0001-000000000007', '00000000-0000-0000-0000-000000000001', 'demo-0007-demo', '$6$pcapcaperseed$s9oPmN3M5.HaH36YaYQ4MdI8NFpagGrvEmKdVXp/4Kut3Ec/2KTJtJIksgPm9mmnFTv9.Rvt2eF1HHel73n5S.'),
    ('00000000-0000-0000-0001-000000000008', '00000000-0000-0000-0000-000000000001', 'demo-0008-demo', '$6$pcapcaperseed$OVmvcIwfRA2.NrNeKOuwVX7.IcT2vaU/rJ/YXXcypEzs1skpAvBkp3RVznpXqdDKw3Rh2dDw3Ehx42XkANdqr0'),
    ('00000000-0000-0000-0001-000000000009', '00000000-0000-0000-0000-000000000001', 'demo-0009-demo', '$6$pcapcaperseed$GGV1.z0udmnyzsc6SMaNNDlAC/75dAbFVKz1QZyxtFlsWq6.Ycm1v3qrP4gPdswdjIJUGAlVAEMZy6hEnRbA4.'),
    ('00000000-0000-0000-0001-000000000010', '00000000-0000-0000-0000-000000000001', 'demo-0010-demo', '$6$pcapcaperseed$Lukza8ZiBqHUxRBFtPDqBUdOFYQUKvsV.En9gnWG9xnOthnjPcTIS/OuLwLssvfxROfqo1bLvktKJ03.5rpk0/')
ON CONFLICT (id) DO NOTHING;
