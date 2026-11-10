<?php
/**
 * Google authorization-code flow with PKCE.
 *
 * @package WPACL
 */

namespace AzraKadric\WpAuthCustomLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Start URL, callback, and the WordPress session that follows a verified token.
 *
 * @since 1.0.0
 */
class Google_OAuth {

	const START_VAR    = 'wpacl_google_start';
	const CALLBACK_VAR = 'wpacl_google_callback';

	/**
	 * Hooks rewrite rules and the callback.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function register() {
		add_action( 'init', array( self::class, 'add_rewrites' ) );
		add_filter( 'query_vars', array( self::class, 'query_vars' ) );
		add_action( 'template_redirect', array( self::class, 'dispatch' ), 0 );
	}

	/**
	 * Registers the public routes and flushes permalinks.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function activate() {
		self::add_rewrites();
		flush_rewrite_rules();
	}

	/**
	 * Drops the public routes on deactivation.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function deactivate() {
		flush_rewrite_rules();
	}

	/**
	 * Adds the two front-end routes.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function add_rewrites() {
		add_rewrite_rule( '^google-login/?$', 'index.php?' . self::START_VAR . '=1', 'top' );
		add_rewrite_rule( '^google-auth-callback/?$', 'index.php?' . self::CALLBACK_VAR . '=1', 'top' );
	}

	/**
	 * Exposes the route flags as query vars.
	 *
	 * @since 1.0.0
	 *
	 * @param string[] $vars Query vars.
	 * @return string[]
	 */
	public static function query_vars( $vars ) {
		$vars[] = self::START_VAR;
		$vars[] = self::CALLBACK_VAR;
		return $vars;
	}

	/**
	 * Runs the start or callback route.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function dispatch() {
		if ( '1' === (string) get_query_var( self::START_VAR ) ) {
			self::start();
		}
		if ( '1' === (string) get_query_var( self::CALLBACK_VAR ) ) {
			self::callback();
		}
	}

	/**
	 * Public URL of the button. Matches the rewrite above.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public static function start_url() {
		return home_url( '/google-login/' );
	}

	/**
	 * Redirect URI registered in Google Cloud Console. Trailing slash included.
	 *
	 * This is the home URL, the address visitors use, not site_url().
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public static function redirect_uri() {
		return home_url( '/google-auth-callback/' );
	}

	/**
	 * Sends the browser to Google, or stops when the flow cannot start safely.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	private static function start() {
		nocache_headers();

		if ( ! Credentials::is_configured() ) {
			self::fail( __( 'Google sign-in is not configured.', 'wp-auth-custom-login' ) );
		}

		$state     = OAuth_State::random_token( 32 );
		$verifier  = OAuth_State::random_token( 32 );
		$challenge = OAuth_State::base64url( hash( 'sha256', $verifier, true ) );

		if ( ! OAuth_State::remember( $state, $verifier ) ) {
			self::fail( __( 'Google sign-in could not be started. Please try again.', 'wp-auth-custom-login' ) );
		}

		$url = add_query_arg(
			array(
				'client_id'             => Credentials::client_id(),
				'redirect_uri'          => self::redirect_uri(),
				'response_type'         => 'code',
				'scope'                 => 'openid email profile',
				'state'                 => $state,
				'code_challenge'        => $challenge,
				'code_challenge_method' => 'S256',
				'prompt'                => 'select_account',
			),
			'https://accounts.google.com/o/oauth2/v2/auth'
		);

		add_filter( 'allowed_redirect_hosts', array( self::class, 'allow_google_host' ) );
		$location = wp_validate_redirect( $url, false );
		if ( ! is_string( $location ) || '' === $location ) {
			self::fail( __( 'Google sign-in could not be started. Please try again.', 'wp-auth-custom-login' ) );
		}

		wp_safe_redirect( $location );
		exit;
	}

	/**
	 * Allows the authorization redirect to leave the site.
	 *
	 * Added immediately before that redirect and not used for anything else.
	 *
	 * @since 1.0.0
	 *
	 * @param string[] $hosts Allowed hosts.
	 * @return string[]
	 */
	public static function allow_google_host( $hosts ) {
		$hosts[] = 'accounts.google.com';
		return $hosts;
	}

	/**
	 * Exchanges the code and signs the matching WordPress user in.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	private static function callback() {
		nocache_headers();

		// Google redirects the browser here. The state comparison is the CSRF check.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- OAuth state replaces a WordPress nonce.
		$saved = OAuth_State::consume();
		$state = isset( $_GET['state'] )
			? sanitize_text_field( wp_unslash( $_GET['state'] ) )
			: '';

		if (
			! is_array( $saved )
			|| ! preg_match( '/\A[A-Za-z0-9\-_]{20,128}\z/', $state )
			|| ! hash_equals( $saved['state'], $state )
		) {
			self::fail( __( 'Invalid Google sign-in attempt.', 'wp-auth-custom-login' ), 403 );
		}

		$google_error = isset( $_GET['error'] )
			? sanitize_text_field( wp_unslash( $_GET['error'] ) )
			: '';
		if ( '' !== $google_error ) {
			self::fail( __( 'Google sign-in was cancelled.', 'wp-auth-custom-login' ) );
		}

		// sanitize_text_field() deletes %HH sequences, which a Google code may contain.
		// The pattern below is the allowlist: printable ASCII, no whitespace, capped length.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Allowlisted on the next lines.
		$code = isset( $_GET['code'] ) ? wp_unslash( $_GET['code'] ) : '';
		$code = is_string( $code ) ? $code : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		if ( ! preg_match( '/\A[\x21-\x7E]{1,2048}\z/', $code ) ) {
			self::fail( __( 'Invalid Google sign-in attempt.', 'wp-auth-custom-login' ), 403 );
		}

		if ( ! Credentials::is_configured() ) {
			self::fail( __( 'Google sign-in is not configured.', 'wp-auth-custom-login' ) );
		}

		$claims = self::exchange( $code, (string) $saved['verifier'] );
		if ( is_wp_error( $claims ) ) {
			self::fail( __( 'Google sign-in failed.', 'wp-auth-custom-login' ) );
		}

		self::login_from_claims( $claims );
	}

	/**
	 * Trades the authorization code for a verified ID token.
	 *
	 * @since 1.0.0
	 *
	 * @param string $code     Authorization code.
	 * @param string $verifier PKCE code verifier stored for this state.
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function exchange( $code, $verifier ) {
		$response = wp_remote_post(
			'https://oauth2.googleapis.com/token',
			array(
				'timeout' => 15,
				'body'    => array(
					'code'          => $code,
					'client_id'     => Credentials::client_id(),
					'client_secret' => Credentials::client_secret(),
					'redirect_uri'  => self::redirect_uri(),
					'grant_type'    => 'authorization_code',
					'code_verifier' => $verifier,
				),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return new \WP_Error( 'wpacl_token', 'Token endpoint rejected the code.' );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || empty( $body['id_token'] ) || ! is_string( $body['id_token'] ) ) {
			return new \WP_Error( 'wpacl_token', 'Token response did not include an ID token.' );
		}

		return Id_Token::verify( $body['id_token'], Credentials::client_id() );
	}

	/**
	 * Signs in the WordPress user for a verified email, creating one when registration is open.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed> $claims Verified ID token claims.
	 * @return void
	 */
	private static function login_from_claims( $claims ) {
		$email = sanitize_email( (string) $claims['email'] );
		if ( ! is_email( $email ) ) {
			self::fail( __( 'Google did not return a usable email address.', 'wp-auth-custom-login' ) );
		}

		$user = get_user_by( 'email', $email );
		if ( ! $user instanceof \WP_User ) {
			if ( ! get_option( 'users_can_register' ) ) {
				self::fail( __( 'Registration is closed, and there is no account for that Google email.', 'wp-auth-custom-login' ) );
			}
			$user = self::provision( $email, (string) $claims['sub'] );
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, true );
		do_action( 'wp_login', $user->user_login, $user );

		wp_safe_redirect( home_url( '/' ) );
		exit;
	}

	/**
	 * Creates a subscriber for a Google account that has no WordPress user yet.
	 *
	 * @since 1.0.0
	 *
	 * @param string $email Verified email.
	 * @param string $sub   Google subject.
	 * @return \WP_User
	 */
	private static function provision( $email, $sub ) {
		$user_id = wp_create_user(
			self::username_from_email( $email ),
			wp_generate_password( 32, true, true ),
			$email
		);

		if ( is_wp_error( $user_id ) ) {
			self::fail( __( 'The WordPress account could not be created.', 'wp-auth-custom-login' ) );
		}

		$subject = substr( sanitize_text_field( $sub ), 0, 255 );
		if ( '' !== $subject ) {
			update_user_meta( $user_id, 'wpacl_google_sub', $subject );
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $user instanceof \WP_User ) {
			self::fail( __( 'The WordPress account could not be created.', 'wp-auth-custom-login' ) );
		}

		return $user;
	}

	/**
	 * Builds a unique login from an email address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $email Email address.
	 * @return string
	 */
	private static function username_from_email( $email ) {
		$base = sanitize_user( str_replace( '@', '_', $email ), true );
		$base = trim( $base, '._-' );
		if ( '' === $base ) {
			$base = 'google_user';
		}
		$base = substr( $base, 0, 48 );

		$candidate = $base;
		$suffix    = 1;
		while ( username_exists( $candidate ) ) {
			$candidate = $base . '_' . $suffix;
			++$suffix;
			if ( $suffix > 100 ) {
				$candidate = $base . '_' . wp_generate_password( 6, false, false );
				break;
			}
		}

		return $candidate;
	}

	/**
	 * Stops the flow with a plain message. Details stay out of the response.
	 *
	 * @since 1.0.0
	 *
	 * @param string $message Already translated message.
	 * @param int    $status  HTTP status.
	 * @return void
	 */
	private static function fail( $message, $status = 400 ) {
		wp_die(
			esc_html( $message ),
			esc_html__( 'Google sign-in', 'wp-auth-custom-login' ),
			array(
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTTP status code, not markup.
				'response'  => (int) $status,
				'back_link' => true,
			)
		);
		exit;
	}
}
