<?php
/**
 * Wires the plugin hooks together.
 *
 * @package WPACL
 */

namespace AzraKadric\WpAuthCustomLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Bootstrap.
 *
 * @since 1.0.0
 */
class Plugin {

	/**
	 * Registers every component.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function boot() {
		Credentials::register();
		Auth_Redirect::register();
		Templates::register();
		Registration::register();
		Google_OAuth::register();
	}
}
