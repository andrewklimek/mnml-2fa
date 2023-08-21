<?php
namespace mnml2fa;
/**
 * Plugin Name: Mnml Two-Factor Authentication
 * Plugin URI:  https://github.com/andrewklimek/mnml-2fa
 * Description: 2-factor authentication on the native login form.  Email and SMS via Twilio
 * Version:     1.1
 * Author:      Andrew Klimek
 * Author URI:  https://github.com/andrewklimek
 * License:     GPLv2 or later
 * License URI: http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */
defined('ABSPATH') || exit;

$settings = (object) get_option( 'mnml2fa', array() );
if ( !empty($settings->twilio_account_sid) && !empty($settings->twilio_api_sid) && !empty($settings->twilio_api_secret) && !empty($settings->twilio_from) ) {
	require __DIR__ . '/twilio.php';
}

add_action( 'login_form_2fa', __NAMESPACE__.'\login_form' );
add_filter( 'authenticate', __NAMESPACE__.'\authenticate', 21, 2 );// normal password checks are on 20, cookie is on 30.  Run inbetween to intercept password logins but not cookie
// authenticate filter https://github.com/WordPress/WordPress/blob/c6028577a462f235da67e5d3dcf1dc42f9a96669/wp-includes/pluggable.php#L575

if ( !empty($settings->auto_login_link) ) {
	add_action( 'login_form', __NAMESPACE__.'\get_link_button' );
	add_action( 'login_form', __NAMESPACE__.'\signon_link_styles', 0 );
	// this would be ebtter but Formidable doesnt use it.
	// add_action( 'login_head', __NAMESPACE__.'\signon_link_styles' );

	add_action( 'after_setup_theme', __NAMESPACE__.'\signon' );
}

function signon() {
	if ( !empty( $_GET['mnml2fakey'] ) ) {
		$user = wp_signon();
	}
}

add_action( 'rest_api_init', __NAMESPACE__ .'\register_api_endpoint' );
function register_api_endpoint() {
	register_rest_route( 'mnml2fa/v1', '/sendlink', ['methods' => 'POST', 'callback' => __NAMESPACE__ .'\api_send_link', 'permission_callback' => '__return_true' ] );
}

function api_send_link( $request ) {
	$data = $request->get_params();
	// error_log( var_export($data, 1));
	if ( empty( $data['login'] ) ) return;
	$user = get_user_by('login', $data['login'] );
	
	if ( ! $user && strpos( $data['login'], '@' ) ) {
		$data['login'] = sanitize_user( wp_unslash( $data['login'] ) );// this is done before the login check as well on ligon.php but get_user_by sanitizes for 'login' case... see https://github.com/WordPress/wordpress-develop/blob/847328068d8d5fef10cd76df635fafd6b47556d9/src/wp-login.php#L1214
		$user = get_user_by( 'email', $data['login'] );
	}

	if ( ! $user ) 	return "Check your email for the sign in link!";// Dont want to admit the user doesnt esists

	$key = bin2hex( random_bytes(16) );// 2nd code hidden in the code form, to make it even more impossible
	
	$link = esc_url( site_url( 'wp-login.php' ) ) . "?mnml2fakey={$key}";
	$subject = "Your sign-in link";
	$body = "<a href='{$link}'>click to sign in!</a>";// default
	$headers = ['Content-Type: text/html;'];
	$email = $user->data->user_email;// $user->get('user_email')

	// get custom text
	
	// if ( !empty($settings->email_subject) ) {
	// 	$subject = str_ireplace( '%code%', $code, $settings->email_subject );
	// }
	// if ( !empty($settings->email_body) ) {
	// 	$body = str_ireplace( '%code%', $code, $settings->email_body, $n );
	// 	if (0===$n) $body .= " $code";// add the code on the end if they didn't use the %code% merge tag in their message
	// }
	$sent = wp_mail( $email, $subject, $body, $headers );

	if ( ! $sent ) {
		return "problem sending";
	}
	set_transient( "mnml2fa_{$key}", $user->ID, 300 );
	return "Check your email for the sign in link!";
}


function get_link_button() {

	// echo "<div style='display:flex;align-items:center'><div style='height:1px;width:50%;background:currentColor'></div><div style='padding:1ex'>OR</div><div style='height:1px;width:50%;background:currentColor'></div></div>";
	?>
	<button id=mnml-magic-link>Get Sign-on Link</button>
	<script>
		// document.querySelector('#mnml-magic-link').onclick = e => {
		document.querySelector('form').onsubmit = e => {
			e.preventDefault();
			var login = document.querySelector('[name=log]').value;
			if ( login )
			fetch('/wp-json/mnml2fa/v1/sendlink',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"login":"'+login+'"}'}).then(r=>{return r.json()}).then(r=>{e.target.innerText=r});
		}
	</script>
	<?php

}
 
function signon_link_styles() {
	?>
<style>
.login-password, .frm_submit,/* formidable */
.user-pass-wrap {
	display: none;
}
</style>
	<?php
}


function authenticate( $user, $user_name ) {

	// only run if $user is a user object, which means user/pass were accepted
	if ( $user instanceof \WP_User ) {
		// is user that needs 2fa

		if ( ! $user->has_cap('administrator') ) return $user;
		
		// if ( $_SERVER['REMOTE_ADDR'] === '0000000' ) return $user;
		
		$settings = (object) get_option( 'mnml2fa', array() );
		
		$code = sprintf( "%06s", random_int(0, 999999) );// six digit code
		$key = bin2hex( random_bytes(16) );// 2nd code hidden in the code form, to make it even more impossible
		
		$sent = false;
		if ( function_exists(__NAMESPACE__.'\send_via_twilio') && $phone = get_user_meta( $user->ID, 'mnml2fano', true ) ) {
			$sent = send_via_twilio( $phone, $code );
		}
		if ( ! $sent ) {

			$email = $user->data->user_email;// $user->get('user_email')
			if ( ! $email ) {
				error_log("no email in mnml2fa");
				exit;
			}
			
			$subject = $body = "Your security code is $code";// default
			// get custom text
			
			if ( !empty($settings->email_subject) ) {
				$subject = str_ireplace( '%code%', $code, $settings->email_subject );
			}
			if ( !empty($settings->email_body) ) {
				$body = str_ireplace( '%code%', $code, $settings->email_body, $n );
				if (0===$n) $body .= " $code";// add the code on the end if they didn't use the %code% merge tag in their message
			}
			$sent = wp_mail( $email, $subject, $body );
		}

		if ( $sent ) {
			set_transient( "mnml2fa_{$code}{$key}", $user->ID, 300 );
			$redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? "&redirect_to=" . $_REQUEST['redirect_to'] : "";
			wp_safe_redirect( "wp-login.php?action=2fa&k=" . $key . $redirect_to );
			exit;
		} else {
			error_log("not sent");
		}
	}
	elseif ( !empty( $_POST['mnml2facode'] ) && !empty( $_POST['mnml2fakey'] ) )
	{
		$settings = (object) get_option( 'mnml2fa', array() );
		
		$user_id = get_transient("mnml2fa_{$_POST['mnml2facode']}{$_POST['mnml2fakey']}");
		
		if ( ! $user_id ) {
			error_log("transient did not exist for code {$_POST['mnml2facode']} key {$_POST['mnml2fakey']}");
		} else {
			$user = get_user_by('id', $user_id);
			// error_log( "logged in user {$user->data->user_login} from IP {$_SERVER['REMOTE_ADDR']}");
			if ( empty($settings->no_login_alerts ) ) {
				$message = "New login from IP {$_SERVER['REMOTE_ADDR']}";
				wp_mail( $user->data->user_email, $message, $message . "\n\nuser agent: {$_SERVER['HTTP_USER_AGENT']}" );
			}
		}
	}
	elseif ( !empty( $_GET['mnml2fakey'] ) )
	{
		$settings = (object) get_option( 'mnml2fa', array() );
		
		$user_id = get_transient("mnml2fa_{$_GET['mnml2fakey']}");
		
		if ( ! $user_id ) {
			error_log("transient did not exist for code key {$_GET['mnml2fakey']}");
		} else {
			$user = get_user_by('id', $user_id);
			// error_log( "logged in user {$user->data->user_login} from IP {$_SERVER['REMOTE_ADDR']}");
			if ( empty($settings->no_login_alerts ) ) {
				$message = "New login from IP {$_SERVER['REMOTE_ADDR']}";
				wp_mail( $user->data->user_email, $message, $message . "\n\nuser agent: {$_SERVER['HTTP_USER_AGENT']}" );
			}
		}
	}
	return $user;
}


function login_form(){

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

add_action( 'rest_api_init', __NAMESPACE__.'\register_options_endpoint' );
function register_options_endpoint() {
	register_rest_route( __NAMESPACE__.'/v1', '/settings', ['methods' => 'POST', 'callback' => __NAMESPACE__.'\api_options', 'permission_callback' => function(){ return current_user_can('manage_options');} ] );
}

function api_options( $request ) {
	$data = $request->get_params();
	foreach ( $data as $k => $v ) update_option( $k, array_filter($v, 'strlen') );
	return "Saved";
}


add_action( 'admin_menu', __NAMESPACE__.'\admin_menu' );
function admin_menu() {
	add_submenu_page( 'options-general.php', 'Mnml 2FA', 'Mnml 2FA', 'edit_users', 'mnml2fa', __NAMESPACE__.'\settings_page' );
}

function settings_page() {

	$fields = array_fill_keys([
		'auto_login_link',
		'email_subject', 'email_body',
		'sms_message',
		'no_login_alerts',
		'twilio_account_sid', 'twilio_api_sid', 'twilio_api_secret', 'twilio_from',
	],
	[ 'type' => 'text' ]);// default

	$fields['auto_login_link']['type'] = 'checkbox';
	$fields['email_body']['type'] = $fields['sms_message']['type'] = 'textarea';
	$fields['email_body']['placeholder'] = $fields['sms_message']['placeholder'] = $fields['email_subject']['placeholder'] = 'Your security code is %code%';
	$fields['no_login_alerts']['type'] = 'checkbox';
	$fields['no_login_alerts']['desc'] = 'Disable new login alert emails';
	$fields['twilio_account_sid']['before'] = "<h3>Twilio settings for SMS codes instead of email</h3>";



	/**
	 *  Build Settings Page using framework in settings_page.php
	 **/
	$options = [ 'mnml2fa' => $fields ];// can add additional options groups to save as their own array in the options table
	$endpoint = rest_url(__NAMESPACE__.'/v1/settings');
	$title = "2FA Settings";
	require( __DIR__.'/settings-page.php' );// needs $options, $endpoint, $title
}
