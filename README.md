# Hybrid OIDC Authorization Server

A fully functional OpenID Connect (OIDC) Authorization Server implemented in Node.js/Express. This server supports **Authorization Code Flow with PKCE** and features two authentication methods:
1.  **Delegated Identity**: Username/Password authentication.
2.  **Passkeys (WebAuthn)**: Native FIDO2 passwordless authentication.

## Features

-   **OIDC Compliant**: Implements Discovery, JWKS, Authorization, Token, and UserInfo endpoints.
-   **PKCE Support**: Mandatory Proof Key for Code Exchange for enhanced security.
-   **Passkey Support**: Full WebAuthn registration and authentication ceremonies.
-   **Server-Side Rendering**: All views rendered using Handlebars.
-   **SQLite Database**: Lightweight, zero-configuration storage.

## Prerequisites

-   Node.js (v16+)
-   npm

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/iprajwaal/oidc-server.git
    cd oidc-server
    ```

2.  Install dependencies:
    ```bash
    npm install
    ```

## Usage

1.  Start the server:
    ```bash
    npm start
    ```
    The server will run on `http://localhost:3000`.

2.  **Test Client**: The server comes seeded with a test client:
    -   **Client ID**: `oidc-client-test`
    -   **Redirect URI**: `http://localhost:3000/callback`
    -   **Secret**: `secret` (optional for PKCE public clients)

3.  **Initiate Login**:
    Visit the following URL to start an OIDC flow:
    [http://localhost:3000/authorize?client_id=oidc-client-test&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&state=123&code_challenge=xyz&code_challenge_method=plain](http://localhost:3000/authorize?client_id=oidc-client-test&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&state=123&code_challenge=xyz&code_challenge_method=plain)

## Authentication Methods

### Password Login
-   **Username**: Any string (e.g., `prajwal`).
-   **Password**: The username reversed (e.g., `lawjarp`) OR `password`.

### Passkey Login
1.  Log in with a password first.
2.  Go to `http://localhost:3000/profile` to register a new Passkey.
3.  Logout and use the "Login with Passkey" button on the login page.

## Project Structure

-   `src/server.js`: Main Express application and route definitions.
-   `src/oidc.js`: OIDC protocol implementation (Token generation, PKCE validation).
-   `src/auth.js`: Authentication logic (Password check, WebAuthn).
-   `src/database.js`: SQLite database schema and connection.
-   `views/`: Handlebars templates for Login, Consent, and Registration.

## License

MIT
