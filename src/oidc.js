const { db } = require('./database');
const jose = require('jose');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const ISSUER = 'http://localhost:3000'; // TODO: Make configurable

// Generate or load keys (for simplicity, generating on startup in memory for this demo)
// In production, these should be persisted.
let privateKey;
let publicKey;
let jwks;

async function initializeKeys() {
    const { publicKey: pub, privateKey: priv } = await jose.generateKeyPair('RS256');
    privateKey = priv;
    publicKey = pub;

    const jwk = await jose.exportJWK(publicKey);
    jwk.kid = 'simpleserver-key-1';
    jwk.use = 'sig';
    jwk.alg = 'RS256';

    jwks = { keys: [jwk] };
    console.log('Keys generated');
}

initializeKeys();

function getDiscovery() {
    return {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        userinfo_endpoint: `${ISSUER}/userinfo`,
        jwks_uri: `${ISSUER}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        scopes_supported: ['openid', 'profile', 'email'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name']
    };
}

function getJWKS() {
    return jwks;
}

function validateClient(clientId, redirectUri) {
    const stmt = db.prepare('SELECT * FROM clients WHERE client_id = ?');
    const client = stmt.get(clientId);

    if (!client) return null;

    const allowedUris = JSON.parse(client.redirect_uris);
    if (!allowedUris.includes(redirectUri)) return null;

    return client;
}

function createAuthCode(clientId, redirectUri, scope, sub, codeChallenge, codeChallengeMethod) {
    const code = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    const stmt = db.prepare(`
    INSERT INTO auth_codes (code, client_id, redirect_uri, scope, sub, code_challenge, code_challenge_method, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

    stmt.run(code, clientId, redirectUri, scope, sub, codeChallenge, codeChallengeMethod, expiresAt);
    return code;
}

async function exchangeCode(code, clientId, clientSecret, redirectUri, codeVerifier) {
    const stmt = db.prepare('SELECT * FROM auth_codes WHERE code = ?');
    const authCode = stmt.get(code);

    if (!authCode) throw new Error('Invalid code');
    if (Date.now() > authCode.expires_at) throw new Error('Code expired');
    if (authCode.client_id !== clientId) throw new Error('Invalid client');
    if (authCode.redirect_uri !== redirectUri) throw new Error('Invalid redirect_uri');

    // PKCE Validation
    if (authCode.code_challenge) {
        if (!codeVerifier) throw new Error('Missing code_verifier');

        let calculatedChallenge;
        if (authCode.code_challenge_method === 'S256') {
            const hash = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
            calculatedChallenge = hash;
        } else {
            calculatedChallenge = codeVerifier; // plain
        }

        if (calculatedChallenge !== authCode.code_challenge) {
            throw new Error('Invalid code_verifier');
        }
    }

    // Verify Client Secret (if provided/required - for confidential clients)
    // For this simple implementation, we check if client exists and secret matches if provided
    const clientStmt = db.prepare('SELECT * FROM clients WHERE client_id = ?');
    const client = clientStmt.get(clientId);
    if (!client) throw new Error('Client not found');
    if (client.client_secret && client.client_secret !== clientSecret) {
        throw new Error('Invalid client_secret');
    }

    // Generate Tokens
    const now = Math.floor(Date.now() / 1000);

    // ID Token
    const idToken = await new jose.SignJWT({
        sub: authCode.sub,
        name: await getUserName(authCode.sub), // Helper to get name
        aud: clientId,
        iss: ISSUER,
        iat: now,
        exp: now + 3600
    })
        .setProtectedHeader({ alg: 'RS256', kid: 'simpleserver-key-1' })
        .sign(privateKey);

    // Access Token (opaque for this example, or JWT)
    // Using JWT for access token too for simplicity in verification, but opaque is fine
    const accessToken = await new jose.SignJWT({
        sub: authCode.sub,
        scope: authCode.scope,
        client_id: clientId
    })
        .setProtectedHeader({ alg: 'RS256', kid: 'simpleserver-key-1' })
        .setIssuedAt()
        .setIssuer(ISSUER)
        .setAudience('api')
        .setExpirationTime('1h')
        .sign(privateKey);

    // Delete used code
    db.prepare('DELETE FROM auth_codes WHERE code = ?').run(code);

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: idToken
    };
}

function getUserName(sub) {
    const stmt = db.prepare('SELECT name FROM users WHERE sub = ?');
    const user = stmt.get(sub);
    return user ? user.name : 'Unknown';
}

function getUserInfo(sub) {
    const stmt = db.prepare('SELECT sub, name, username FROM users WHERE sub = ?');
    return stmt.get(sub);
}

module.exports = {
    getDiscovery,
    getJWKS,
    validateClient,
    createAuthCode,
    exchangeCode,
    getUserInfo
};
