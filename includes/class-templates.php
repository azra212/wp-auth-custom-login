<?php
/**
 * Registers the login and registration page templates.
 *
 * @package WPACL
 */

namespace AzraKadric\WpAuthCustomLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin page templates.
 *
 * @since 1.0.0
 */
class Templates {

	const LOGIN    = 'templates/login.php';
	const REGISTER = 'templates/register.php';

	/**
	 * Hooks template registration, loading, and the login test cookie.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function register() {
		add_filter( 'theme_page_templates', array( self::class, 'add' ) );
		add_filter( 'template_include', array( self::class, 'load' ) );
		add_action( 'wp_enqueue_scripts', array( self::class, 'enqueue' ) );
		add_action( 'template_redirect', array( self::class, 'set_test_cookie' ), 1 );
	}

	/**
	 * Adds the two templates to the page editor.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, string> $templates Template slug => label.
	 * @return array<string, string>
	 */
	public static function add( $templates ) {
		$templates[ self::LOGIN ]    = __( 'Custom Login Page', 'wp-auth-custom-login' );
		$templates[ self::REGISTER ] = __( 'Custom Register Page', 'wp-auth-custom-login' );
		return $templates;
	}

	/**
	 * Loads a plugin template when the page is assigned one of ours.
	 *
	 * The slug is compared to a fixed list. It is never joined onto a path.
	 *
	 * @since 1.0.0
	 *
	 * @param string $template Theme template WordPress already chose.
	 * @return string
	 */
	public static function load( $template ) {
		$slug = get_page_template_slug();
		$map  = array(
			self::LOGIN    => WPACL_PATH . self::LOGIN,
			self::REGISTER => WPACL_PATH . self::REGISTER,
		);

		if ( ! isset( $map[ $slug ] ) || ! is_readable( $map[ $slug ] ) ) {
			return $template;
		}

		return $map[ $slug ];
	}

	/**
	 * Styles used by both auth templates.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function enqueue() {
		if ( ! is_page_template( self::LOGIN ) && ! is_page_template( self::REGISTER ) ) {
			return;
		}

		wp_enqueue_style(
			'wpacl-auth',
			plugins_url( 'assets/css/auth.css', WPACL_FILE ),
			array(),
			WPACL_VERSION
		);
	}

	/**
	 * Sets the core test cookie so a later POST to wp-login.php is accepted.
	 *
	 * The core login screen sets this cookie itself. That screen is not
	 * rendered here, because the GET is redirected to this page.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function set_test_cookie() {
		if ( self::LOGIN !== get_page_template_slug() || isset( $_COOKIE[ TEST_COOKIE ] ) ) {
			return;
		}

		if ( headers_sent() ) {
			return;
		}

		$path   = COOKIEPATH ? COOKIEPATH : '/';
		$domain = is_string( COOKIE_DOMAIN ) ? COOKIE_DOMAIN : '';

		setcookie( TEST_COOKIE, 'WP Cookie check', 0, $path, $domain, is_ssl(), true );
	}

	/**
	 * Front-end URL of the custom login page.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public static function login_url() {
		return home_url( '/login/' );
	}

	/**
	 * Front-end URL of the custom registration page.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public static function register_url() {
		return home_url( '/register/' );
	}
}
