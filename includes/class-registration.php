<?php
/**
 * Handles the custom registration form before any HTML is sent.
 *
 * @package WPACL
 */

namespace AzraKadric\WpAuthCustomLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registration requests.
 *
 * @since 1.0.0
 */
class Registration {

	/**
	 * Messages for the template. Empty unless this request failed validation.
	 *
	 * @var string[]
	 */
	private static $errors = array();

	/**
	 * Hooks request handling.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function register() {
		add_action( 'template_redirect', array( self::class, 'handle' ), 1 );
	}

	/**
	 * Validation messages for the current request.
	 *
	 * @since 1.0.0
	 *
	 * @return string[]
	 */
	public static function errors() {
		return self::$errors;
	}

	/**
	 * Creates a user from a valid registration POST, or records errors.
	 *
	 * Runs on template_redirect so a success can redirect before output.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function handle() {
		if ( Templates::REGISTER !== get_page_template_slug() ) {
			return;
		}

		$method = isset( $_SERVER['REQUEST_METHOD'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) )
			: '';

		if ( 'POST' !== $method ) {
			return;
		}

		$nonce = isset( $_POST['wpacl_register_nonce'] )
			? sanitize_text_field( wp_unslash( $_POST['wpacl_register_nonce'] ) )
			: '';

		if ( ! wp_verify_nonce( $nonce, 'wpacl_register' ) ) {
			self::$errors[] = __( 'The registration form expired. Please try again.', 'wp-auth-custom-login' );
			return;
		}

		if ( is_user_logged_in() ) {
			self::$errors[] = __( 'You are already logged in.', 'wp-auth-custom-login' );
			return;
		}

		if ( ! get_option( 'users_can_register' ) ) {
			self::$errors[] = __( 'Registration is closed.', 'wp-auth-custom-login' );
			return;
		}

		$username = isset( $_POST['username'] )
			? sanitize_user( wp_unslash( $_POST['username'] ), true )
			: '';
		$email    = isset( $_POST['email'] )
			? sanitize_email( wp_unslash( $_POST['email'] ) )
			: '';

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- wp_create_user() hashes the password. Sanitizing it would change the secret.
		$password = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : '';
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Compared with the password and then discarded.
		$confirm = isset( $_POST['password_confirm'] ) ? (string) wp_unslash( $_POST['password_confirm'] ) : '';

		self::$errors = self::validate( $username, $email, $password, $confirm );
		if ( self::$errors ) {
			return;
		}

		$user_id = wp_create_user( $username, $password, $email );
		if ( is_wp_error( $user_id ) ) {
			self::$errors[] = __( 'Registration failed. Please try again.', 'wp-auth-custom-login' );
			return;
		}

		self::sign_in( (int) $user_id );
	}

	/**
	 * Collects every problem with the submitted fields.
	 *
	 * @since 1.0.0
	 *
	 * @param string $username Sanitized username.
	 * @param string $email    Sanitized email.
	 * @param string $password Raw password.
	 * @param string $confirm  Raw confirmation.
	 * @return string[]
	 */
	private static function validate( $username, $email, $password, $confirm ) {
		$errors = array();

		if ( '' === $username ) {
			$errors[] = __( 'Username is required.', 'wp-auth-custom-login' );
		} elseif ( strlen( $username ) > 60 ) {
			$errors[] = __( 'Username is too long.', 'wp-auth-custom-login' );
		} elseif ( username_exists( $username ) ) {
			$errors[] = __( 'Username already exists.', 'wp-auth-custom-login' );
		}

		if ( '' === $email || ! is_email( $email ) ) {
			$errors[] = __( 'A valid email address is required.', 'wp-auth-custom-login' );
		} elseif ( strlen( $email ) > 100 ) {
			$errors[] = __( 'Email is too long.', 'wp-auth-custom-login' );
		} elseif ( email_exists( $email ) ) {
			$errors[] = __( 'Email already registered.', 'wp-auth-custom-login' );
		}

		if ( '' === $password ) {
			$errors[] = __( 'Password is required.', 'wp-auth-custom-login' );
		} elseif ( strlen( $password ) < 6 ) {
			$errors[] = __( 'Password must be at least 6 characters.', 'wp-auth-custom-login' );
		} elseif ( strlen( $password ) > 4096 ) {
			$errors[] = __( 'Password is too long.', 'wp-auth-custom-login' );
		} elseif ( ! hash_equals( $password, $confirm ) ) {
			$errors[] = __( 'Passwords do not match.', 'wp-auth-custom-login' );
		}

		return $errors;
	}

	/**
	 * Starts a WordPress session for a user this request just created.
	 *
	 * @since 1.0.0
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	private static function sign_in( $user_id ) {
		$user = get_user_by( 'id', $user_id );

		wp_set_current_user( $user_id );
		wp_set_auth_cookie( $user_id, true );

		if ( $user instanceof \WP_User ) {
			do_action( 'wp_login', $user->user_login, $user );
		}

		wp_safe_redirect( home_url( '/' ) );
		exit;
	}
}
