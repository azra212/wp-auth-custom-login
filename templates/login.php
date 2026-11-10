<?php
/**
 * Custom login page.
 *
 * The form posts to wp-login.php. This template does not call wp_signon().
 * Assign it to a page whose slug is "login".
 *
 * @package WPACL
 */

use AzraKadric\WpAuthCustomLogin\Templates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();
?>
<div class="login-form-container">
	<h2><?php esc_html_e( 'Prijava', 'wp-auth-custom-login' ); ?></h2>
	<form method="post" action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ); ?>">
		<p>
			<label for="wpacl-login"><?php esc_html_e( 'Korisničko ime', 'wp-auth-custom-login' ); ?></label>
			<input type="text" name="log" id="wpacl-login" autocomplete="username" required>
		</p>
		<p>
			<label for="wpacl-password"><?php esc_html_e( 'Šifra', 'wp-auth-custom-login' ); ?></label>
			<input type="password" name="pwd" id="wpacl-password" autocomplete="current-password" required>
		</p>
		<input type="hidden" name="redirect_to" value="<?php echo esc_url( admin_url() ); ?>">
		<input type="hidden" name="testcookie" value="1">
		<p>
			<input type="submit" name="wp-submit" value="<?php esc_attr_e( 'Prijavi se', 'wp-auth-custom-login' ); ?>">
		</p>
	</form>

	<div class="wpacl-divider">
		<p><?php esc_html_e( 'Ili', 'wp-auth-custom-login' ); ?></p>
		<?php
		$wpacl_label = __( 'Prijavi se sa Google-om', 'wp-auth-custom-login' );
		require WPACL_PATH . 'templates/partials/google-link.php';
		?>
	</div>

	<div class="wpacl-switch">
		<p>
			<?php esc_html_e( 'Nemate račun?', 'wp-auth-custom-login' ); ?>
			<a href="<?php echo esc_url( Templates::register_url() ); ?>"><?php esc_html_e( 'Registrujte se ovdje', 'wp-auth-custom-login' ); ?></a>
		</p>
	</div>
</div>
<?php
get_footer();
