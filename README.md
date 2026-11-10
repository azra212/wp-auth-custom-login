# WP Auth Custom Login

Custom login and registration screens, plus Google sign-in, for a WordPress site that still wants core to own users, sessions, cookies, and capabilities.

The pages live in this plugin. `wp-login.php` still performs authentication.

## Redirect the UI, not the auth

Hooking `login_init` and redirecting every hit of `wp-login.php` also redirects the POST that checks the password, and it gets in the way of logout and password reset. Those requests are the auth engine. The screen is not.

This plugin hooks `login_form_login`, which runs for the login action only.

- A GET is sent to the `/login/` page with `wp_safe_redirect()`.
- A POST returns immediately, so the submitted username and password are still handled by `wp-login.php`.
- Logout, lost password, password reset, and the interim login modal never enter this hook.

Google is an identity provider. After the ID token checks out, the plugin calls `wp_set_auth_cookie()` and fires the core `wp_login` action. It does not invent a session and it does not store Google tokens.

## What it does

- Page templates for `/login/` and `/register/`, shipped in this plugin rather than a theme
- Username and password login posted to `wp-login.php`
- Registration on the custom page, following Settings → General → "Anyone can register"
- Google OAuth with PKCE, a single-use state, and ID token checks
- An admin notice when the Google constants are missing from `wp-config.php`

## What it leaves to WordPress

- The address `wp-login.php`
- Logout, password reset, and the interim login modal
- Cookies and capabilities
- MFA, CAPTCHA, rate limiting, and branding

## Requirements

- WordPress 6.0 or newer
- PHP 8.1 or newer
- HTTPS anywhere Google will redirect to. Localhost over HTTP is the usual local exception.
- Pretty permalinks. Plain permalinks do not serve the Google routes.

## Setup

1. Copy this repository into `wp-content/plugins/wp-auth-custom-login` and activate **WP Auth Custom Login**. Composer is only for development. The plugin runs without `vendor/`.
2. In Google Cloud Console, create an OAuth client of type **Web application**. Add this authorized redirect URI, with the site's real origin and the trailing slash:

   `https://example.com/google-auth-callback/`

   That value is `home_url( '/google-auth-callback/' )`, the public site address. Use `home_url()`, including when WordPress itself lives in a subdirectory.

3. In `wp-config.php`, above "That's all, stop editing":

   ```php
   define( 'WPACL_GOOGLE_CLIENT_ID', 'your-id.apps.googleusercontent.com' );
   define( 'WPACL_GOOGLE_CLIENT_SECRET', 'your-secret' );
   ```

   The secret stays in `wp-config.php`. It is not stored in the database. Administrators see an error notice on admin screens until both constants are non-empty. The notice does not print the secret.

4. Create a page with slug `login` and assign the **Custom Login Page** template. Create a page with slug `register` and assign the **Custom Register Page** template. Both templates are registered by the plugin. The active theme still renders the header and footer.
5. If `/google-login/` 404s after a permalink change, open Settings → Permalinks and save. Activation flushes rewrite rules once.
6. To allow new accounts, enable Settings → General → Membership → "Anyone can register". With that option off, the register form and a first-time Google sign-in will not create users. An email that already has a WordPress account can still sign in with Google.

## Google sign-in

1. `/google-login/` redirects to Google with `response_type=code`, a `state`, and a PKCE `code_challenge` (`S256`). The `code_verifier` and `state` are stored for 10 minutes. The browser gets an HttpOnly cookie that points at that record. `SameSite=Lax`, so the cookie is present on the top-level return from Google. The authorization URL includes the client id and never includes the secret.
2. `/google-auth-callback/` reads the cookie, deletes the record, and continues only when `state` matches and the record has not expired. The code is exchanged with the verifier and the client secret.
3. The ID token is checked locally. The signature must match a current Google signing key (`RS256` from `https://www.googleapis.com/oauth2/v3/certs`). `iss` must be `https://accounts.google.com` or `accounts.google.com`. `aud` must be this site's client id. `exp` must still be in the future, with 60 seconds of clock skew. `email_verified` must be true. The email and subject come from those claims.

The plugin does not call Google's userinfo endpoint. The access token and the ID token are discarded after the check. `accounts.google.com` is added to `allowed_redirect_hosts` only for the authorization redirect, which still goes through `wp_safe_redirect()`.

## Security notes

- Treat `WPACL_GOOGLE_CLIENT_SECRET` like a database password. Do not commit it.
- State is single-use and bound to the browser that started the flow. A callback without that cookie is rejected. The expiry is stored on the record itself, so a cache that ignores transient timeouts cannot keep it alive.
- Output is escaped. Registration has its own nonce. Passwords are passed to `wp_create_user()`, which hashes them. The authorization code is allowlisted as printable ASCII because `sanitize_text_field()` would strip `%HH` sequences inside it.
- Uninstall removes the `wpacl_google_sub` user meta and the cached Google signing keys, then flushes rewrite rules. In-flight OAuth records expire within 10 minutes.
- This is a reference implementation. Rate limiting, MFA, and CAPTCHA belong in front of `wp-login.php`, the same way they would on any other WordPress site.

## Layout

```
wp-auth-custom-login.php
uninstall.php
readme.txt
includes/
assets/css/auth.css
templates/login.php
templates/register.php
templates/partials/google-link.php
docs/screenshots/
```

## Development

```bash
composer install
composer phpcs
```

GitHub Actions runs PHPCS, and `php -l` on PHP 8.1, 8.2, 8.3, and 8.4.

## Screenshots

The sample copy on the screenshots is Bosnian, and the templates keep that copy.

### Login

![Custom login page](docs/screenshots/login-page.png)

### Register

![Custom registration page](docs/screenshots/register-page.png)

## License

[GPL-2.0-or-later](LICENSE).

## Author

Azra Kadrić
