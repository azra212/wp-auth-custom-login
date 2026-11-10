<?php
/**
 * Removes data stored by WP Auth Custom Login.
 *
 * In-flight OAuth state lives in short transients (10 minutes) whose names
 * include a random key. Those rows expire on their own. The callback route
 * is gone once the plugin is uninstalled, and the PKCE verifier was only
 * useful with that route.
 *
 * @package WPACL
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_transient( 'wpacl_google_jwks' );
delete_metadata( 'user', 0, 'wpacl_google_sub', '', true );

flush_rewrite_rules();
