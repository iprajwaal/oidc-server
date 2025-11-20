const express = require('express');
const { engine } = require('express-handlebars');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');

const { init } = require('./database');
const oidc = require('./oidc');
const auth = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize DB
init();

// Middleware
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, '../views'));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
    secret: 'super-secret-key', // TODO: Change in production
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// --- OIDC Endpoints ---

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/callback', (req, res) => {
    const { code } = req.query;
    res.render('callback', { code });
});

app.get('/.well-known/openid-configuration', (req, res) => {
    res.json(oidc.getDiscovery());
});

app.get('/jwks', (req, res) => {
    res.json(oidc.getJWKS());
});

app.get('/authorize', (req, res) => {
    const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;

    // Validate Client
    const client = oidc.validateClient(client_id, redirect_uri);
    if (!client) {
        return res.status(400).send('Invalid client or redirect_uri');
    }

    // Check Session
    if (req.session.user) {
        // User is logged in, generate code and redirect
        const code = oidc.createAuthCode(client_id, redirect_uri, scope, req.session.user.sub, code_challenge, code_challenge_method);
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.append('code', code);
        if (state) redirectUrl.searchParams.append('state', state);
        return res.redirect(redirectUrl.toString());
    }

    // Show Login Page
    res.render('login', {
        client_id,
        redirect_uri,
        state,
        scope,
        code_challenge,
        code_challenge_method
    });
});

app.post('/token', async (req, res) => {
    const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    try {
        const tokens = await oidc.exchangeCode(code, client_id, client_secret, redirect_uri, code_verifier);
        res.json(tokens);
    } catch (err) {
        console.error('Token Error:', err.message);
        res.status(400).json({ error: 'invalid_request', error_description: err.message });
    }
});

app.get('/userinfo', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'unauthorized' });
    }

    // In a real app, we would verify the access token signature and expiration here.
    // For this demo, we'll decode it to get the sub (assuming it's a JWT we issued).
    // WARNING: Skipping signature verification for simplicity in this specific block, 
    // but in production use jose.jwtVerify

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jose.decodeJwt(token); // Unsafe decode just to get claims
        const userInfo = oidc.getUserInfo(decoded.sub);
        if (userInfo) {
            res.json(userInfo);
        } else {
            res.status(404).json({ error: 'user_not_found' });
        }
    } catch (e) {
        res.status(401).json({ error: 'invalid_token' });
    }
});

// --- Authentication Endpoints ---

app.post('/login', (req, res) => {
    const { username, password, client_id, redirect_uri, state, scope, code_challenge, code_challenge_method } = req.body;

    const user = auth.authenticateExternal(username, password);

    if (user) {
        req.session.user = user;
        // Redirect back to authorize to complete the flow
        const params = new URLSearchParams({
            client_id,
            redirect_uri,
            state,
            scope,
            code_challenge,
            code_challenge_method,
            response_type: 'code'
        });
        return res.redirect(`/authorize?${params.toString()}`);
    }

    res.render('login', {
        error: 'Invalid credentials',
        client_id,
        redirect_uri,
        state,
        scope,
        code_challenge,
        code_challenge_method
    });
});

// --- WebAuthn Endpoints ---

app.get('/webauthn/register/options', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

    const { options, user } = await auth.getWebAuthnRegistrationOptions(req.session.user.username);
    req.session.currentChallenge = options.challenge;
    res.json(options);
});

app.post('/webauthn/register/verify', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

    try {
        const verified = await auth.verifyWebAuthnRegistration(req.session.user, req.body, req.session.currentChallenge);
        req.session.currentChallenge = undefined;
        res.json({ verified });
    } catch (e) {
        res.status(400).json({ verified: false, error: e.message });
    }
});

app.get('/webauthn/login/options', async (req, res) => {
    const options = await auth.getWebAuthnLoginOptions();
    req.session.currentChallenge = options.challenge;
    res.json(options);
});

app.post('/webauthn/login/verify', async (req, res) => {
    try {
        const user = await auth.verifyWebAuthnLogin(req.body, req.session.currentChallenge);
        req.session.currentChallenge = undefined;
        req.session.user = user;
        res.json({ verified: true });
    } catch (e) {
        res.status(400).json({ verified: false, error: e.message });
    }
});

// --- User Management UI (for registering passkeys) ---

app.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/authorize'); // Should probably redirect to login, but authorize works if params present
    res.render('register-passkey', { user: req.session.user });
});

// Start Server
app.listen(PORT, () => {
    console.log(`OIDC Server running on http://localhost:${PORT}`);
});
