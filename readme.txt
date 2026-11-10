=== WP Auth Custom Login ===
Contributors: azrakadric
Tags: login, registration, oauth, google
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 1.0.0
Requires PHP: 8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Custom login and registration pages with Google sign-in. WordPress still owns authentication.

== Description ==

WP Auth Custom Login replaces the login and registration screens. It does not replace WordPress authentication.

The login screen is redirected from `login_form_login`. That hook runs for the login action only. A GET goes to the custom `/login/` page. A POST is left alone, so `wp-login.php` still checks the password. Logout, lost password, and password reset keep the core screens.

Google is used as an identity provider. The plugin verifies the ID token (signature, `aud`, `iss`, `exp`) and then calls `wp_set_auth_cookie()`.

Client credentials are read from `wp-config.php`:

`
define( 'WPACL_GOOGLE_CLIENT_ID', 'your-id.apps.googleusercontent.com' );
define( 'WPACL_GOOGLE_CLIENT_SECRET', 'your-secret' );
`

Administrators see an error notice until both constants are set. The notice does not print the secret.

= Security =

* PKCE (`S256`) and a single-use `state` stored for 10 minutes, bound to an HttpOnly cookie.
* ID token signature checked against Google's JWKS. `iss`, `aud`, and `exp` are checked. `email_verified` must be true.
* The userinfo endpoint is not used. Access tokens and ID tokens are not stored.
* Output is escaped, input is sanitized, and redirects use `wp_safe_redirect()`.
* New accounts, including first-time Google sign-in, follow Settings → General → "Anyone can register".

Screenshots of the bundled templates are in `docs/screenshots/` in the Git repository.

== Installation ==

1. Upload the plugin directory to `/wp-content/plugins/wp-auth-custom-login` and activate it.
2. Create a Google OAuth web client. Set the authorized redirect URI to the public site URL plus `/google-auth-callback/` (trailing slash included).
3. Define `WPACL_GOOGLE_CLIENT_ID` and `WPACL_GOOGLE_CLIENT_SECRET` in `wp-config.php`.
4. Create pages with slugs `login` and `register`. Assign the Custom Login Page and Custom Register Page templates.
5. Use any permalink structure other than Plain.
6. Enable "Anyone can register" if new visitors should be able to create accounts.

The templates use the active theme's header and footer.

== Frequently Asked Questions ==

= Does this disable wp-login.php? =

No. The file stays where it is. Only the login screen is redirected. Password checks, logout, and password reset still run there.

= Where do I put the Google client secret? =

In `wp-config.php`, as `WPACL_GOOGLE_CLIENT_SECRET`. Do not put it in the database or in the theme.

= What happens on uninstall? =

The plugin deletes the `wpacl_google_sub` user meta and the cached Google signing keys, then flushes rewrite rules. Users and passwords are left in place. OAuth state records expire on their own within 10 minutes.

== Screenshots ==

1. Custom login page. The form posts to wp-login.php.
2. Custom registration page.

The image files live in `docs/screenshots/` in the Git repository.

== Changelog ==

= 1.0.0 =
* First release of the restructured plugin: templates live in the plugin, Google credentials come from wp-config.php, and the OAuth callback verifies the ID token.

== Upgrade Notice ==

= 1.0.0 =
Define WPACL_GOOGLE_CLIENT_ID and WPACL_GOOGLE_CLIENT_SECRET in wp-config.php before using Google sign-in.
