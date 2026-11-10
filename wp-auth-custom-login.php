<?php
/**
 * Custom login and registration screens. Google is only an identity provider.
 *
 * Plugin Name:       WP Auth Custom Login
 * Plugin URI:        https://github.com/azra212/wp-auth-custom-login
 * Description:       Custom login and registration pages with Google sign-in. WordPress remains the authentication engine.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * Author:            Azra Kadrić
 * Author URI:        https://github.com/azra212
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-auth-custom-login
 *
 * @package WPACL
 */

namespace AzraKadric\WpAuthCustomLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPACL_VERSION', '1.0.0' );
define( 'WPACL_FILE', __FILE__ );
define( 'WPACL_PATH', plugin_dir_path( __FILE__ ) );

require_once WPACL_PATH . 'includes/class-plugin.php';
require_once WPACL_PATH . 'includes/class-credentials.php';
require_once WPACL_PATH . 'includes/class-oauth-state.php';
require_once WPACL_PATH . 'includes/class-id-token.php';
require_once WPACL_PATH . 'includes/class-google-oauth.php';
require_once WPACL_PATH . 'includes/class-auth-redirect.php';
require_once WPACL_PATH . 'includes/class-registration.php';
require_once WPACL_PATH . 'includes/class-templates.php';

register_activation_hook( __FILE__, array( Google_OAuth::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( Google_OAuth::class, 'deactivate' ) );

add_action( 'plugins_loaded', array( Plugin::class, 'boot' ) );
