<?php
/**
 * Custom registration page.
 *
 * The POST is handled on template_redirect, before this file renders.
 * Assign it to a page whose slug is "register".
 *
 * @package WPACL
 */

use AzraKadric\WpAuthCustomLogin\Registration;
use AzraKadric\WpAuthCustomLogin\Templates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();
?>
<div class="login-form-container">
	<h2><?php esc_html_e( 'Registruj se', 'wp-auth-custom-login' ); ?></h2>

	<?php if ( get_option( 'users_can_register' ) ) : ?>
		<form method="post">
			<?php wp_nonce_field( 'wpacl_register', 'wpacl_register_nonce' ); ?>
			<p>
				<label for="wpacl-register-username"><?php esc_html_e( 'Korisničko ime', 'wp-auth-custom-login' ); ?></label>
				<input type="text" name="username" id="wpacl-register-username" autocomplete="username" required>
			</p>
			<p>
				<label for="wpacl-register-email"><?php esc_html_e( 'Email', 'wp-auth-custom-login' ); ?></label>
				<input type="email" name="email" id="wpacl-register-email" autocomplete="email" required>
			</p>
			<p>
				<label for="wpacl-register-password"><?php esc_html_e( 'Šifra', 'wp-auth-custom-login' ); ?></label>
				<input type="password" name="password" id="wpacl-register-password" autocomplete="new-password" required>
			</p>
			<p>
				<label for="wpacl-register-password-confirm"><?php esc_html_e( 'Potvrdi Šifru', 'wp-auth-custom-login' ); ?></label>
				<input type="password" name="password_confirm" id="wpacl-register-password-confirm" autocomplete="new-password" required>
			</p>
			<p>
				<input type="submit" name="wpacl_register" value="<?php esc_attr_e( 'Registruj se', 'wp-auth-custom-login' ); ?>">
			</p>
		</form>
	<?php else : ?>
		<p><?php esc_html_e( 'Registration is closed.', 'wp-auth-custom-login' ); ?></p>
	<?php endif; ?>

	<div class="wpacl-divider">
		<p><?php esc_html_e( 'Ili', 'wp-auth-custom-login' ); ?></p>
		<?php
		$wpacl_label = __( 'Registruj se sa Google-om', 'wp-auth-custom-login' );
		require WPACL_PATH . 'templates/partials/google-link.php';
		?>
	</div>

	<div class="wpacl-switch">
		<p>
			<?php esc_html_e( 'Već imate račun?', 'wp-auth-custom-login' ); ?>
			<a href="<?php echo esc_url( Templates::login_url() ); ?>"><?php esc_html_e( 'Prijavite se ovdje', 'wp-auth-custom-login' ); ?></a>
		</p>
	</div>

	<?php $wpacl_errors = Registration::errors(); ?>
	<?php if ( $wpacl_errors ) : ?>
		<div class="wpacl-errors" role="alert">
			<?php foreach ( $wpacl_errors as $wpacl_error ) : ?>
				<p><?php echo esc_html( $wpacl_error ); ?></p>
			<?php endforeach; ?>
		</div>
	<?php endif; ?>
</div>
<?php
get_footer();
