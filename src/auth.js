const { db } = require('./database');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const { v4: uuidv4 } = require('uuid');

const RP_NAME = 'OIDC Server';
const RP_ID = 'localhost';
const ORIGIN = 'http://localhost:3000';

// --- Delegated Identity (U/P) ---

function authenticateExternal(username, password) {
    // Dummy implementation: Accept any password that matches the username (reversed) or simple 'password'
    // In a real scenario, this would check a hash or call an external API.
    if (password === 'password' || password === username.split('').reverse().join('')) {
        // Check if user exists, if not create
        let stmt = db.prepare('SELECT * FROM users WHERE username = ?');
        let user = stmt.get(username);

        if (!user) {
            const sub = uuidv4();
            const name = username.charAt(0).toUpperCase() + username.slice(1);
            db.prepare('INSERT INTO users (sub, username, name) VALUES (?, ?, ?)').run(sub, username, name);
            user = { sub, username, name };
        }
        return user;
    }
    return null;
}

// --- WebAuthn (Passkeys) ---

async function getWebAuthnRegistrationOptions(username) {
    // Ensure user exists or create a temporary one for registration context
    let stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    let user = stmt.get(username);

    if (!user) {
        // For registration, we might want to create the user upfront or handle it differently.
        // Here we create it if it doesn't exist to have a user.id
        const sub = uuidv4();
        const name = username.charAt(0).toUpperCase() + username.slice(1);
        db.prepare('INSERT INTO users (sub, username, name) VALUES (?, ?, ?)').run(sub, username, name);
        user = { sub, username, name };
    }

    const userCredentials = db.prepare('SELECT credential_id, transports FROM credentials WHERE user_sub = ?').all(user.sub);

    const options = await generateRegistrationOptions({
        rpName: RP_NAME,
        rpID: RP_ID,
        userID: new Uint8Array(Buffer.from(user.sub)),
        userName: user.username,
        attestationType: 'none',
        excludeCredentials: userCredentials.map(cred => ({
            id: cred.credential_id,
            transports: cred.transports ? JSON.parse(cred.transports) : undefined,
        })),
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'preferred',
            authenticatorAttachment: 'platform',
        },
    });

    return { options, user };
}

async function verifyWebAuthnRegistration(user, body, currentChallenge) {
    const verification = await verifyRegistrationResponse({
        response: body,
        expectedChallenge: currentChallenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
    });

    if (verification.verified && verification.registrationInfo) {
        const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

        // Save credential
        const id = uuidv4();
        db.prepare(`
      INSERT INTO credentials (id, credential_id, public_key, sign_count, user_sub, transports)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
            id,
            Buffer.from(credentialID).toString('base64url'),
            Buffer.from(credentialPublicKey).toString('base64url'),
            counter,
            user.sub,
            JSON.stringify(body.response.transports || []) // Save transports if available
        );

        return true;
    }
    return false;
}

async function getWebAuthnLoginOptions() {
    const options = await generateAuthenticationOptions({
        rpID: RP_ID,
        userVerification: 'preferred',
    });
    return options;
}

async function verifyWebAuthnLogin(body, currentChallenge) {
    const credentialId = body.id;
    const stmt = db.prepare('SELECT * FROM credentials WHERE credential_id = ?');
    const credential = stmt.get(credentialId);

    if (!credential) {
        throw new Error('Credential not found');
    }

    const userStmt = db.prepare('SELECT * FROM users WHERE sub = ?');
    const user = userStmt.get(credential.user_sub);

    const verification = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge: currentChallenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        authenticator: {
            credentialID: credential.credential_id,
            credentialPublicKey: new Uint8Array(Buffer.from(credential.public_key, 'base64url')),
            counter: credential.sign_count,
        },
    });

    if (verification.verified) {
        // Update counter
        db.prepare('UPDATE credentials SET sign_count = ? WHERE id = ?')
            .run(verification.authenticationInfo.newCounter, credential.id);

        return user;
    }
    throw new Error('Verification failed');
}

module.exports = {
    authenticateExternal,
    getWebAuthnRegistrationOptions,
    verifyWebAuthnRegistration,
    getWebAuthnLoginOptions,
    verifyWebAuthnLogin
};
