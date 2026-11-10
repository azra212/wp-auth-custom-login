<?php
/**
 * Binds an OAuth state and PKCE verifier to the browser that started the flow.
 *
 * The cookie only holds a lookup key. The state and the code verifier stay
 * in a transient with its own expiry timestamp, so a cache that ignores
 * transient timeouts cannot keep the record alive.
 *
 * @package WPACL
 */

namespace AzraKadric\WpAuthCustomLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Per-browser OAuth state.
 *
 * @since 1.0.0
 */
class OAuth_State {

	const COOKIE = 'wpacl_oauth';
	const PREFIX = 'wpacl_oa_';
	const TTL    = 600;

	/**
	 * Stores a new state and sets the session cookie.
	 *
	 * @since 1.0.0
	 *
	 * @param string $state    Opaque value sent to Google.
	 * @param string $verifier PKCE code verifier. Never sent to the browser.
	 * @return bool False when the transient or the cookie could not be stored.
	 */
	public static function remember( $state, $verifier ) {
		$key = self::random_token( 16 );
		$ok  = set_transient(
			self::PREFIX . $key,
			array(
				'state'    => $state,
				'verifier' => $verifier,
				'expires'  => time() + self::TTL,
			),
			self::TTL
		);

		if ( ! $ok ) {
			return false;
		}

		if ( ! self::set_cookie( $key, time() + self::TTL ) ) {
			delete_transient( self::PREFIX . $key );
			return false;
		}

		return true;
	}

	/**
	 * Reads and deletes the record for this browser.
	 *
	 * @since 1.0.0
	 *
	 * @return array{state: string, verifier: string}|null Null when missing or expired.
	 */
	public static function consume() {
		$key = self::read_cookie();
		self::clear_cookie();

		if ( '' === $key ) {
			return null;
		}

		$name = self::PREFIX . $key;
		$data = get_transient( $name );
		delete_transient( $name );

		if ( ! is_array( $data ) ) {
			return null;
		}

		$state    = isset( $data['state'] ) ? (string) $data['state'] : '';
		$verifier = isset( $data['verifier'] ) ? (string) $data['verifier'] : '';
		if ( '' === $state || '' === $verifier ) {
			return null;
		}

		$expires = isset( $data['expires'] ) ? (int) $data['expires'] : 0;
		if ( $expires < time() ) {
			return null;
		}

		return array(
			'state'    => $state,
			'verifier' => $verifier,
		);
	}

	/**
	 * URL-safe random token.
	 *
	 * @since 1.0.0
	 *
	 * @param int $bytes Number of random bytes. 32 bytes is a 43 character verifier.
	 * @return string Base64url, without padding.
	 */
	public static function random_token( $bytes = 32 ) {
		return self::base64url( random_bytes( $bytes ) );
	}

	/**
	 * Encodes raw bytes as unpadded base64url.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bytes Raw bytes.
	 * @return string
	 */
	public static function base64url( $bytes ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- PKCE and OAuth state are unpadded base64url.
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}

	/**
	 * Sets the HttpOnly session cookie.
	 *
	 * SameSite=Lax so the cookie is still sent on the top-level GET
	 * back from accounts.google.com.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value   Lookup key.
	 * @param int    $expires Unix timestamp.
	 * @return bool
	 */
	private static function set_cookie( $value, $expires ) {
		if ( headers_sent() ) {
			return false;
		}

		return setcookie( self::COOKIE, $value, self::cookie_options( $expires ) );
	}

	/**
	 * Expires the session cookie.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	private static function clear_cookie() {
		if ( headers_sent() ) {
			return;
		}

		setcookie( self::COOKIE, '', self::cookie_options( time() - HOUR_IN_SECONDS ) );
	}

	/**
	 * Reads and checks the lookup key.
	 *
	 * @since 1.0.0
	 *
	 * @return string Empty when the cookie is missing or malformed.
	 */
	private static function read_cookie() {
		if ( ! isset( $_COOKIE[ self::COOKIE ] ) ) {
			return '';
		}

		$key = sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) );
		if ( ! preg_match( '/\A[A-Za-z0-9\-_]{20,128}\z/', $key ) ) {
			return '';
		}

		return $key;
	}

	/**
	 * Options shared by set and clear so the browser actually drops the cookie.
	 *
	 * @since 1.0.0
	 *
	 * @param int $expires Unix timestamp.
	 * @return array<string, mixed>
	 */
	private static function cookie_options( $expires ) {
		$path   = COOKIEPATH ? COOKIEPATH : '/';
		$domain = is_string( COOKIE_DOMAIN ) ? COOKIE_DOMAIN : '';

		return array(
			'expires'  => $expires,
			'path'     => $path,
			'domain'   => $domain,
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		);
	}
}
