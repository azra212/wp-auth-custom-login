<?php
/**
 * Sends people from the core login screen to the custom page.
 *
 * @package WPACL
 */

namespace AzraKadric\WpAuthCustomLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Login-screen redirect.
 *
 * `login_form_login` runs for the login action only, so logout, lost password,
 * and password reset keep the core screens. POST is returned untouched so a
 * submitted username and password are still handled by wp-login.php.
 *
 * @since 1.0.0
 */
class Auth_Redirect {

	/**
	 * Hooks the login screen.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function register() {
		add_action( 'login_form_login', array( self::class, 'redirect_login_screen' ) );
	}

	/**
	 * Redirects a GET of the login screen to the custom page.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function redirect_login_screen() {
		$method = isset( $_SERVER['REQUEST_METHOD'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) )
			: '';

		if ( 'POST' === $method ) {
			return;
		}

		// The modal login opens wp-login.php in an iframe. Redirecting it breaks core.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Core flag, value unused.
		if ( isset( $_REQUEST['interim-login'] ) ) {
			return;
		}

		wp_safe_redirect( Templates::login_url() );
		exit;
	}
}
