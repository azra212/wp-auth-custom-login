<?php
/**
 * Reads the Google OAuth client from wp-config.php.
 *
 * Define both constants above the "That's all, stop editing" line:
 *
 *     define( 'WPACL_GOOGLE_CLIENT_ID', '....apps.googleusercontent.com' );
 *     define( 'WPACL_GOOGLE_CLIENT_SECRET', '...' );
 *
 * The secret never goes in the database, an option, or this repository.
 *
 * @package WPACL
 */

namespace AzraKadric\WpAuthCustomLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Google client credentials.
 *
 * @since 1.0.0
 */
class Credentials {

	const CLIENT_ID     = 'WPACL_GOOGLE_CLIENT_ID';
	const CLIENT_SECRET = 'WPACL_GOOGLE_CLIENT_SECRET';

	/**
	 * Shows an admin notice while either constant is missing.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function register() {
		add_action( 'admin_notices', array( self::class, 'notice' ) );
	}

	/**
	 * Whether both constants are present and non-empty.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public static function is_configured() {
		return '' !== self::client_id() && '' !== self::client_secret();
	}

	/**
	 * Public OAuth client id.
	 *
	 * @since 1.0.0
	 *
	 * @return string Empty when the constant is missing or not a string.
	 */
	public static function client_id() {
		return self::constant_string( self::CLIENT_ID );
	}

	/**
	 * OAuth client secret.
	 *
	 * @since 1.0.0
	 *
	 * @return string Empty when the constant is missing or not a string.
	 */
	public static function client_secret() {
		return self::constant_string( self::CLIENT_SECRET );
	}

	/**
	 * Error notice for administrators. The secret is never printed.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function notice() {
		if ( ! current_user_can( 'manage_options' ) || self::is_configured() ) {
			return;
		}

		$missing = array();
		if ( '' === self::client_id() ) {
			$missing[] = self::CLIENT_ID;
		}
		if ( '' === self::client_secret() ) {
			$missing[] = self::CLIENT_SECRET;
		}

		echo '<div class="notice notice-error"><p>';
		printf(
			/* translators: %s: comma-separated wp-config.php constant names. */
			esc_html__( 'Google sign-in needs %s defined in wp-config.php.', 'wp-auth-custom-login' ),
			esc_html( implode( ', ', $missing ) )
		);
		echo '</p></div>';
	}

	/**
	 * Reads a scalar wp-config constant.
	 *
	 * @since 1.0.0
	 *
	 * @param string $name Constant name.
	 * @return string Trimmed value, or an empty string.
	 */
	private static function constant_string( $name ) {
		if ( ! defined( $name ) ) {
			return '';
		}

		$value = constant( $name );
		if ( ! is_string( $value ) && ! is_numeric( $value ) ) {
			return '';
		}

		return trim( (string) $value );
	}
}
