<?php
/**
 * Verifies a Google ID token.
 *
 * Checking aud, iss, and exp is meaningless until the signature is checked
 * against Google's published keys. Claims are read from the verified token.
 * The userinfo endpoint is not used.
 *
 * @package WPACL
 */

namespace AzraKadric\WpAuthCustomLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Google ID token verifier.
 *
 * @since 1.0.0
 */
class Id_Token {

	const CERTS_URL  = 'https://www.googleapis.com/oauth2/v3/certs';
	const CACHE_KEY  = 'wpacl_google_jwks';
	const CLOCK_SKEW = 60;

	/**
	 * Verifies the signature and the claims this plugin relies on.
	 *
	 * @since 1.0.0
	 *
	 * @param string $jwt       Compact JWT from the token endpoint.
	 * @param string $client_id Expected audience.
	 * @return array<string, mixed>|\WP_Error Claims on success.
	 */
	public static function verify( $jwt, $client_id ) {
		if ( ! preg_match( '/\A[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\z/', $jwt ) ) {
			return new \WP_Error( 'wpacl_id_token', 'Malformed ID token.' );
		}

		$parts = explode( '.', $jwt );
		list( $header_b64, $payload_b64, $signature_b64 ) = $parts;

		$header  = json_decode( self::base64url_decode( $header_b64 ), true );
		$payload = json_decode( self::base64url_decode( $payload_b64 ), true );

		if ( ! is_array( $header ) || ! is_array( $payload ) ) {
			return new \WP_Error( 'wpacl_id_token', 'Malformed ID token.' );
		}

		$header_check = self::header_is_acceptable( $header );
		if ( is_wp_error( $header_check ) ) {
			return $header_check;
		}

		$signature = self::base64url_decode( $signature_b64 );
		if ( '' === $signature || ! self::signature_is_valid( $header_b64 . '.' . $payload_b64, $signature, (string) $header['kid'] ) ) {
			return new \WP_Error( 'wpacl_id_token', 'ID token signature was rejected.' );
		}

		if ( ! self::claims_are_valid( $payload, $client_id ) ) {
			return new \WP_Error( 'wpacl_id_token', 'ID token claims were rejected.' );
		}

		return $payload;
	}

	/**
	 * Accepts an RS256 JWT and nothing with a critical extension.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed> $header JOSE header.
	 * @return true|\WP_Error
	 */
	private static function header_is_acceptable( $header ) {
		if ( isset( $header['crit'] ) ) {
			return new \WP_Error( 'wpacl_id_token', 'Unsupported JWT crit header.' );
		}

		if ( isset( $header['typ'] ) && 'JWT' !== $header['typ'] ) {
			return new \WP_Error( 'wpacl_id_token', 'Unexpected JWT typ.' );
		}

		if ( 'RS256' !== ( $header['alg'] ?? '' ) ) {
			return new \WP_Error( 'wpacl_id_token', 'Unexpected JWT alg.' );
		}

		$kid = isset( $header['kid'] ) ? (string) $header['kid'] : '';
		if ( ! preg_match( '/\A[A-Za-z0-9_\-]{1,128}\z/', $kid ) ) {
			return new \WP_Error( 'wpacl_id_token', 'Unexpected JWT kid.' );
		}

		return true;
	}

	/**
	 * Verifies an RS256 signature with the key Google currently publishes for this kid.
	 *
	 * @since 1.0.0
	 *
	 * @param string $signing_input Header and payload, still base64url, joined by a dot.
	 * @param string $signature     Raw signature bytes.
	 * @param string $kid           Key id from the JOSE header.
	 * @return bool
	 */
	private static function signature_is_valid( $signing_input, $signature, $kid ) {
		$pem = self::pem_for_kid( $kid );
		if ( '' === $pem ) {
			return false;
		}

		$key = openssl_pkey_get_public( $pem );
		if ( false === $key ) {
			return false;
		}

		return 1 === openssl_verify( $signing_input, $signature, $key, OPENSSL_ALGO_SHA256 );
	}

	/**
	 * Checks issuer, audience, expiry, and that Google has verified the email.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed> $claims    Token payload.
	 * @param string               $client_id Expected audience.
	 * @return bool
	 */
	private static function claims_are_valid( $claims, $client_id ) {
		$issuer  = isset( $claims['iss'] ) ? (string) $claims['iss'] : '';
		$issuers = array( 'https://accounts.google.com', 'accounts.google.com' );
		if ( ! in_array( $issuer, $issuers, true ) ) {
			return false;
		}

		if ( ! self::audience_matches( $claims['aud'] ?? null, $client_id ) ) {
			return false;
		}

		$expires = isset( $claims['exp'] ) ? (int) $claims['exp'] : 0;
		if ( $expires < ( time() - self::CLOCK_SKEW ) ) {
			return false;
		}

		if ( isset( $claims['iat'] ) && (int) $claims['iat'] > ( time() + self::CLOCK_SKEW ) ) {
			return false;
		}

		if ( isset( $claims['nbf'] ) && (int) $claims['nbf'] > ( time() + self::CLOCK_SKEW ) ) {
			return false;
		}

		$subject = isset( $claims['sub'] ) ? (string) $claims['sub'] : '';
		if ( '' === $subject || strlen( $subject ) > 255 ) {
			return false;
		}

		$email = isset( $claims['email'] ) ? (string) $claims['email'] : '';
		if ( '' === $email ) {
			return false;
		}

		return true === ( $claims['email_verified'] ?? null );
	}

	/**
	 * Audience may be a string or a list. It has to include this client id.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed  $audience Raw aud claim.
	 * @param string $client_id Expected client id.
	 * @return bool
	 */
	private static function audience_matches( $audience, $client_id ) {
		if ( '' === $client_id ) {
			return false;
		}

		if ( is_string( $audience ) ) {
			return hash_equals( $client_id, $audience );
		}

		if ( ! is_array( $audience ) ) {
			return false;
		}

		foreach ( $audience as $value ) {
			if ( is_string( $value ) && hash_equals( $client_id, $value ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Builds a PEM public key for a kid, refreshing the cache once on a miss.
	 *
	 * @since 1.0.0
	 *
	 * @param string $kid       Key id.
	 * @param bool   $refreshed Whether the cache was already bypassed.
	 * @return string PEM, or an empty string.
	 */
	private static function pem_for_kid( $kid, $refreshed = false ) {
		foreach ( self::keys( $refreshed ) as $key ) {
			if ( ! is_array( $key ) || ( $key['kid'] ?? '' ) !== $kid ) {
				continue;
			}
			if ( 'RSA' !== ( $key['kty'] ?? '' ) || empty( $key['n'] ) || empty( $key['e'] ) ) {
				return '';
			}
			return self::rsa_pem( (string) $key['n'], (string) $key['e'] );
		}

		if ( $refreshed ) {
			return '';
		}

		delete_transient( self::CACHE_KEY );
		return self::pem_for_kid( $kid, true );
	}

	/**
	 * Returns cached JWKS keys, fetching them when the cache is cold.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $bypass_cache Skip the transient and fetch again.
	 * @return array<int, mixed>
	 */
	private static function keys( $bypass_cache ) {
		if ( ! $bypass_cache ) {
			$cached = get_transient( self::CACHE_KEY );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		}

		$keys = self::fetch_keys();
		if ( $keys ) {
			set_transient( self::CACHE_KEY, $keys, 6 * HOUR_IN_SECONDS );
		}

		return $keys;
	}

	/**
	 * Downloads Google's current signing keys.
	 *
	 * @since 1.0.0
	 *
	 * @return array<int, mixed>
	 */
	private static function fetch_keys() {
		$response = wp_remote_get(
			self::CERTS_URL,
			array(
				'timeout' => 10,
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return array();
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['keys'] ) || ! is_array( $data['keys'] ) ) {
			return array();
		}

		return $data['keys'];
	}

	/**
	 * Encodes an RSA modulus and exponent as a SubjectPublicKeyInfo PEM.
	 *
	 * @since 1.0.0
	 *
	 * @param string $modulus_b64  Base64url modulus (JWK n).
	 * @param string $exponent_b64 Base64url exponent (JWK e).
	 * @return string PEM, or an empty string when the components are unusable.
	 */
	private static function rsa_pem( $modulus_b64, $exponent_b64 ) {
		$modulus  = self::base64url_decode( $modulus_b64 );
		$exponent = self::base64url_decode( $exponent_b64 );
		if ( '' === $modulus || '' === $exponent ) {
			return '';
		}

		if ( ord( $modulus[0] ) > 0x7f ) {
			$modulus = "\x00" . $modulus;
		}
		if ( ord( $exponent[0] ) > 0x7f ) {
			$exponent = "\x00" . $exponent;
		}

		$rsa = self::asn1_sequence( self::asn1_integer( $modulus ) . self::asn1_integer( $exponent ) );

		// rsaEncryption OID 1.2.840.113549.1.1.1 followed by NULL.
		$algorithm = hex2bin( '300d06092a864886f70d0101010500' );
		if ( false === $algorithm ) {
			return '';
		}

		$spki = self::asn1_sequence( $algorithm . self::asn1_bit_string( $rsa ) );

		return "-----BEGIN PUBLIC KEY-----\n"
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- PEM armor for an RSA public key.
			. chunk_split( base64_encode( $spki ), 64, "\n" )
			. "-----END PUBLIC KEY-----\n";
	}

	/**
	 * DER length prefix.
	 *
	 * @since 1.0.0
	 *
	 * @param int $length Number of value bytes.
	 * @return string
	 */
	private static function asn1_length( $length ) {
		if ( $length < 0x80 ) {
			return chr( $length );
		}

		$encoded = ltrim( pack( 'N', $length ), "\x00" );
		return chr( 0x80 | strlen( $encoded ) ) . $encoded;
	}

	/**
	 * DER INTEGER.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bytes Unsigned big-endian contents, already padded if the high bit is set.
	 * @return string
	 */
	private static function asn1_integer( $bytes ) {
		return "\x02" . self::asn1_length( strlen( $bytes ) ) . $bytes;
	}

	/**
	 * DER SEQUENCE.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bytes Concatenated contents.
	 * @return string
	 */
	private static function asn1_sequence( $bytes ) {
		return "\x30" . self::asn1_length( strlen( $bytes ) ) . $bytes;
	}

	/**
	 * DER BIT STRING with no unused bits.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bytes Contents.
	 * @return string
	 */
	private static function asn1_bit_string( $bytes ) {
		$body = "\x00" . $bytes;
		return "\x03" . self::asn1_length( strlen( $body ) ) . $body;
	}

	/**
	 * Decodes unpadded base64url.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Encoded text.
	 * @return string Empty when the input is not base64url.
	 */
	private static function base64url_decode( $value ) {
		$remainder = strlen( $value ) % 4;
		if ( 0 !== $remainder ) {
			$value .= str_repeat( '=', 4 - $remainder );
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- JWT and JWK segments are base64url.
		$decoded = base64_decode( strtr( $value, '-_', '+/' ), true );
		return false === $decoded ? '' : $decoded;
	}
}
