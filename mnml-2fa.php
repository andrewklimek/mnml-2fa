<?php
/**
 * Plugin Name: Mnml Two-Factor Authentication
 * Plugin URI:  https://github.com/andrewklimek/mnml-2fa
 * Description: 2-factor authentication on the native login form.  Email and SMS via Twilio
 * Version:     1.0
 * Author:      Andrew Klimek
 * Author URI:  https://github.com/andrewklimek
 * License:     GPLv2 or later
 * License URI: http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */
defined('ABSPATH') || exit;

$settings = get_option( 'mnml2fa', array() );
if ( !empty($settings['twilio_sid']) && !empty($settings['twilio_api_sid']) && !empty($settings['twilio_api_secret']) && !empty($settings['twilio_from']) ) {
	require __DIR__ . '/twilio.php';
}

add_action( 'login_form_2fa', 'mnml2fa_login_form' );
add_filter( 'authenticate', 'mnml2fa_authenticate', 21, 2 );// normal password checks are on 20, cookie is on 30.  Run inbetween to intercept password logins but not cookie
// authenticate filter https://github.com/WordPress/WordPress/blob/c6028577a462f235da67e5d3dcf1dc42f9a96669/wp-includes/pluggable.php#L575

function mnml2fa_authenticate( $user, $user_name ) {
	// only run if $user is a user object, which means user/pass were accepted
	if ( $user instanceof WP_User ) {
		// is user that needs 2fa
		if ( ! $user->has_cap('administrator') ) return $user;

		$settings = get_option( 'mnml2fa', array() );

		$code = sprintf( "%06s", random_int(0, 999999) );// six digit code
		$key = bin2hex( random_bytes(16) );// 2nd code hidden in the code form, to make it even more impossible
		
		$sent = false;
		if ( function_exists('mnml2fa_send_via_twilio') && $phone = get_user_meta( $user->ID, 'mnml2fano', true ) ) {
			$sent = mnml2fa_send_via_twilio( $phone, $code );
		}
		if ( ! $sent ) {
			$email = $user->data->user_email;// $user->get('user_email')
			if ( ! $email ) {
				error_log("no email in mnml2fa");
				exit;
			}
			
			$subject = $body = "Your security code is $code";// default
			// get custom text
			
			if ( !empty($settings['email_subject']) ) {
				$subject = str_ireplace( '%code%', $code, $settings['email_subject'] );
			}
			if ( !empty($settings['email_body']) ) {
				$body = str_ireplace( '%code%', $code, $settings['email_body'], $n );
				if (0===$n) $body .= " $code";// add the code on the end if they didn't use the %code% merge tag in their message
			}
			$sent = wp_mail( $email, $subject, $body );
		}

		if ( $sent ) {
			set_transient( "mnml2fa_{$code}{$key}", $user->ID, 300 );
			$redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? "&redirect_to=" . $_REQUEST['redirect_to'] : "";
			wp_safe_redirect( "wp-login.php?action=2fa&k=" . $key . $redirect_to );
			exit;
		}
	}
	elseif ( !empty( $_POST['mnml2facode'] ) && !empty( $_POST['mnml2fakey'] ) )
	{
		$settings = get_option( 'mnml2fa', array() );
		
		$user_id = get_transient("mnml2fa_{$_POST['mnml2facode']}{$_POST['mnml2fakey']}");
		
		if ( ! $user_id ) {
			error_log("transient did not exist for code {$_POST['mnml2facode']} key {$_POST['mnml2fakey']}");
		} else {
			$user = get_user_by('id', $user_id);
			// error_log( "logged in user {$user->data->user_login} from IP {$_SERVER['REMOTE_ADDR']}");
			if ( empty($settings['no_login_alerts'] ) ) {
				$message = "New login from IP {$_SERVER['REMOTE_ADDR']}";
				wp_mail( $user->data->user_email, $message, $message . "\n\nuser agent: {$_SERVER['HTTP_USER_AGENT']}" );
			}
		}
	}
	return $user;
}


function mnml2fa_login_form(){

	$redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : home_url();// this should always be set though see https://github.com/WordPress/WordPress/blob/c6028577a462f235da67e5d3dcf1dc42f9a96669/wp-login.php#L1226

	// if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
		// check code

		// either run wp_signon() https://github.com/WordPress/WordPress/blob/c6028577a462f235da67e5d3dcf1dc42f9a96669/wp-includes/user.php#L33
		// or redirect to login 

		// either way probably pass authentication with a filter on 'authenticate'

		// $redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : 'wp-login.php?action=2fa';
		// wp_safe_redirect( $redirect_to );
		// exit;
	// }

	$key = filter_input( INPUT_GET, 'k', FILTER_SANITIZE_STRING );
	if ( ! $key ) {
		error_log("something's wrong, there's no key for 2fa");
		wp_safe_redirect( 'wp-login.php' );
		exit;
	}

	login_header( 'New Device Authentication', '<p class="message">A code was just sent to your security device.  Please enter it to continue.</p>' );
	
	?>
	<style>#mnml2facode::-webkit-inner-spin-button{display:none}</style>
	<form name="2fa" id="2fa" action="<?php echo esc_url( network_site_url( 'wp-login.php', 'login_post' ) ); ?>" method="post">
		<input type="hidden" name="mnml2fakey" value="<?php echo $key; ?>" />
		<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
		<p>
			<input type="number" name="mnml2facode" id="mnml2facode" class="input" size="20"  autocomplete="off" />
		</p>
		<p class="submit">
			<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Submit" />
		</p>
	</form>
	<?php

	login_footer( 'user_login' );

	exit;
}


/************************
* Settings Page
**/

add_action( 'admin_menu', 'mnml2fa_admin_menu' );
add_action( 'admin_init', 'mnml2fa_settings_init' );

function mnml2fa_admin_menu() {
	add_submenu_page( 'options-general.php', 'Mnml 2FA', 'Mnml 2FA', 'edit_users', 'mnml2fa', 'mnml2fa_settings_page' );
}

function mnml2fa_settings_page() {
?>
<div class="wrap">
	<h2>2FA Settings</h2>
	<form action="options.php" method="post">
		<?php settings_fields( 'mnml2fa' ); ?>
		<?php do_settings_sections( 'mnml2fa' ); ?>
		<?php submit_button(); ?>
	</form>
</div>
<?php
}

function mnml2fa_settings_init() {

	$name = 'mnml2fa';
	$existing = get_option( $name );

	register_setting( 'mnml2fa', $name );


	$section = $name . '_general';

	add_settings_section(
		$section,
		'',
		$section .'_section_callback',
		'mnml2fa'
	);
	
	$field = 'email_body';
	add_settings_field(
		"{$name}_{$field}",
		'Email Body',
		'mnml2fa_setting_callback_textarea',
		'mnml2fa',
		$section,
		['label_for' => "{$name}_{$field}", 'name' => "{$name}[{$field}]", 'value' => isset($existing[$field]) ? $existing[$field] : '', 'placeholder' => "Your security code is %code%" ]
	);

	$field = 'email_subject';
	add_settings_field(
		"{$name}_{$field}",
		'Email Subject',
		'mnml2fa_setting_callback_text',
		'mnml2fa',
		$section,
		['label_for' => "{$name}_{$field}", 'name' => "{$name}[{$field}]", 'value' => isset($existing[$field]) ? $existing[$field] : '', 'placeholder' => "Your security code is %code%" ]
	);

	$field = 'sms_message';
	add_settings_field(
		"{$name}_{$field}",
		'SMS Message',
		'mnml2fa_setting_callback_textarea',
		'mnml2fa',
		$section,
		['label_for' => "{$name}_{$field}", 'name' => "{$name}[{$field}]", 'value' => isset($existing[$field]) ? $existing[$field] : '', 'placeholder' => "Your security code is %code%" ]
	);

	$field = 'no_login_alerts';
	add_settings_field(
		"{$name}_{$field}",
		'Disable new login alert emails',
		'mnml2fa_setting_callback_checkbox',
		'mnml2fa',
		$section,
		['label_for' => "{$name}_{$field}", 'name' => "{$name}[{$field}]", 'value' => isset($existing[$field]) ? $existing[$field] : '' ]
	);



	$section = $name . '_twilio';
	
	add_settings_section(
		$section,
		'Twilio',
		$section .'_section_callback',
		'mnml2fa'
	);
	
	$field = 'twilio_sid';
	add_settings_field(
		"{$name}_{$field}",
		'Twilio Account SID',
		'mnml2fa_setting_callback_text',
		'mnml2fa',
		$section,
		['label_for' => "{$name}_{$field}", 'name' => "{$name}[{$field}]", 'value' => isset($existing[$field]) ? $existing[$field] : '', 'placeholder' => "" ]
	);

	$field = 'twilio_api_sid';
	add_settings_field(
		"{$name}_{$field}",
		'Twilio API SID',
		'mnml2fa_setting_callback_text',
		'mnml2fa',
		$section,
		['label_for' => "{$name}_{$field}", 'name' => "{$name}[{$field}]", 'value' => isset($existing[$field]) ? $existing[$field] : '', 'placeholder' => "" ]
	);

	$field = 'twilio_api_secret';
	add_settings_field(
		"{$name}_{$field}",
		'Twilio API Secret',
		'mnml2fa_setting_callback_text',
		'mnml2fa',
		$section,
		['label_for' => "{$name}_{$field}", 'name' => "{$name}[{$field}]", 'value' => isset($existing[$field]) ? $existing[$field] : '', 'placeholder' => "" ]
	);

	$field = 'twilio_from';
	add_settings_field(
		"{$name}_{$field}",
		'Twilio From',
		'mnml2fa_setting_callback_text',
		'mnml2fa',
		$section,
		['label_for' => "{$name}_{$field}", 'name' => "{$name}[{$field}]", 'value' => isset($existing[$field]) ? $existing[$field] : '', 'placeholder' => "" ]
	);

}


function mnml2fa_general_section_callback() {
	// echo "<p>Some help text</p>";
}
function mnml2fa_twilio_section_callback() {
	echo "<p>Twilio settings for SMS codes instead of email</p>";
}
function mnml2fa_setting_callback_text( $args ) {
	printf(
		'<input name="%s" id="%s" placeholder="%s" value="%s" class="regular-text">',
		$args['name'],
		$args['label_for'],
		$args['placeholder'],
		$args['value']
	);
}
function mnml2fa_setting_callback_checkbox( $args ) {
	$checked = $args['value'] ? 'checked' : '';
	printf(
		'<input type="checkbox" name="%s" id="%s" %s>',
		$args['name'],
		$args['label_for'],
		$checked
	);
}
function mnml2fa_setting_callback_textarea( $args ) {
	printf(
		'<textarea name="%s" id="%s" rows="10" class="large-text" placeholder="%s">%s</textarea>',
		$args['name'],
		$args['label_for'],
		$args['placeholder'],
		$args['value']
	);
}