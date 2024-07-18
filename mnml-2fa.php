<?php
namespace mnml2fa;
/**
 * Plugin Name: Mnml Two-Factor Authentication
 * Plugin URI:  https://github.com/andrewklimek/mnml-2fa
 * Description: 2-factor authentication on the native login form.  Email and SMS via Twilio
 * Version:     1.3.1
 * Author:      Andrew Klimek
 * Author URI:  https://github.com/andrewklimek
 * License:     GPLv2 or later
 * License URI: http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */
defined('ABSPATH') || exit;

$settings = (object) get_option( 'mnml2fa', array() );
if ( !empty($settings->twilio_account_sid) && !empty($settings->twilio_api_sid) && !empty($settings->twilio_api_secret) && ( !empty($settings->twilio_from) || !empty($settings->twilio_messaging_service_sid) ) ) {
	require __DIR__ . '/twilio.php';
}

add_action( 'login_form_2fa', __NAMESPACE__.'\login_form' );
add_filter( 'authenticate', __NAMESPACE__.'\authenticate', 21, 2 );// normal password checks are on 20, cookie is on 30.  Run inbetween to intercept password logins but not cookie
// authenticate filter https://github.com/WordPress/WordPress/blob/c6028577a462f235da67e5d3dcf1dc42f9a96669/wp-includes/pluggable.php#L575

if ( !empty($settings->type) && $settings->type == 'link' ) {
	add_action( 'login_form', __NAMESPACE__.'\get_link_button' );
	add_action( 'login_form', __NAMESPACE__.'\signon_link_styles', 0 );
	// the 'login_form' action is not called in wp_login_form() which can be used to insert a simple login form.  The 'login_form_middle' filter is used in that function.
	add_filter( 'login_form_middle', __NAMESPACE__.'\wp_login_form_template', 10, 1 );
	// this would be better but Formidable doesnt use it.
	// add_action( 'login_head', __NAMESPACE__.'\signon_link_styles' );
	// add_filter( 'authenticate', __NAMESPACE__.'\authenticate_link', 19, 3 );

	add_action( 'after_setup_theme', __NAMESPACE__.'\signon' );
}

function wp_login_form_template($html){
	ob_start();
	signon_link_styles();
	get_link_button();
	return ob_get_clean();
}

// this check was ruining the redirect on the portal but i dont really know why... might be something specific on that site
add_filter('admin_email_check_interval', '__return_zero' );

// function authenticate_link( $user, $username, $password ) {
// 	if ( $user instanceof WP_User ) return $user;
// 	if ( empty( $username ) || !empty( $password ) ) return $user;
// 	$user = get_user_by( 'login', $username );
// }

function signon() {
	if ( empty( $_GET['tfal'] ) ) return;
		
	$login_data = get_transient("mnml2fa_{$_GET['tfal']}");
	$login_data = (object) $login_data;
	
	if ( empty($login_data->id) ) return;

	if ( !empty( $login_data->ip ) && $login_data->ip !== $_SERVER['REMOTE_ADDR'] ) {
		error_log("someone clicked magic link from mismatched IP");
		return;
	}

	$creds = [ 'user_login' => '', 'user_password' => '', 'remember' => false ];
	if ( !empty($login_data->rm) || !empty( $_REQUEST['rm'] ) ) {
		$creds['remember'] = true;
	}
	$user = wp_signon( $creds );

	if ( ! empty( $login_data->redirect ) ) {
		wp_safe_redirect( $login_data->redirect );
		exit;
	}
	// wp_safe_redirect( wp_login_url() );
}

add_action( 'rest_api_init', __NAMESPACE__ .'\register_api_endpoint' );
function register_api_endpoint() {
	register_rest_route( 'mnml2fa/v1', '/sendlink', ['methods' => 'POST', 'callback' => __NAMESPACE__ .'\api_send_link', 'permission_callback' => '__return_true' ] );
}

function api_send_link( $request ) {

	if ( empty( $request['mnml2falog'] ) ) return '';

	$settings = (object) get_option( 'mnml2fa', array() );

	$user = false;
	$return = "Check your email for the auto-login link";

	if ( strpos( $request['mnml2falog'], '@' ) ) {
		$request['mnml2falog'] = sanitize_user( wp_unslash( $request['mnml2falog'] ) );// this is done before the login check as well on ligon.php but get_user_by sanitizes for 'login' case... see https://github.com/WordPress/wordpress-develop/blob/847328068d8d5fef10cd76df635fafd6b47556d9/src/wp-login.php#L1214
		$user = get_user_by( 'email', $request['mnml2falog'] );
	} elseif ( function_exists(__NAMESPACE__.'\send_via_twilio') ) {
		$maybe_tel = preg_replace( '/\D/', '', $request['mnml2falog'] );
		if ( strlen( $maybe_tel ) > 8 ) {
			$return = "Check your phone for the auto-login link";
			$user = apply_filters( 'mnml2fa_get_user_by_tele', null, $maybe_tel );// $maybe_tel is sanitized already to digits only
			if ( $user === null ) {
				$meta_key = $settings->telephone_user_meta ?? 'mnml2fano';
				$users = get_users( [ 'meta_key' => $meta_key, 'meta_value' => $maybe_tel, 'number' => 2 ] );
				if ( count( $users ) > 1 ) {
					error_log("two accounts have the same phone number trying to login: $maybe_tel");
				}
				$user = current( $users );
			}
			if ( $user ) $tel = $maybe_tel;// confirm this is a telephone number for use below to flag trigger of sms
		}
	}

	if ( ! $user ) $user = get_user_by('login', $request['mnml2falog'] );

	if ( ! $user ) return $return;// Dont want to admit the user doesnt esists

	do { $key = random(16); } while ( get_transient( "mnml2fa_{$key}" ) );

	$link = get_home_url() . "?tfal={$key}";
	
	$login_data = (object) [ 'id' => $user->ID, 'rm' => 0 ];

	if ( !empty( $request['rememberme'] ) ) {
		$login_data->rm = 1;
	}
	if ( !empty( $request['redirect_to'] ) ) {
		$login_data->redirect = $_REQUEST['redirect_to'];
	}
	if ( !empty( $_SERVER['REMOTE_ADDR'] ) ) {// TODO: this can be a proxy server IP... how to rule that out?
		$login_data->ip = $_SERVER['REMOTE_ADDR'];
	}
	
	$code = false;
	// if ( !empty( $request['mnml2fak'] ) ) {
	if ( !empty( $settings->code_with_magic_link ) ) {
		$code_key = filter_var( $request['mnml2fak'], FILTER_SANITIZE_NUMBER_INT );
		if ( strlen( $code_key ) < 9 ) return "code key was weird";
		$code = sprintf( "%06s", random_int(0, 999999) );// six digit code
		set_transient( "mnml2fa_{$code}{$code_key}", $login_data, 300 );
	}
	if ( !empty( $tel ) ) {
		$sent = send_via_twilio( $tel, $code, $link );
		// error_log( 'send_via_twilio to $tel=' . $tel . ' RESULT: ' . var_export( $sent, 1 ) );
		if ( $sent ) $return = "Check your phone for the auto-login link";
	}
	if ( empty( $sent ) ) {
		$email = $user->user_email;// $user->get('user_email')
		$subject = $settings->link_email_subject ?? "Your sign-in link";
		$body = $settings->link_email_body ?? "Hello %name%, here is the sign-in link you requested";
		$name = " ". $user->first_name ?? " ". $user->display_name ?? "";
		$body = str_ireplace( [" %name%", "%name%" ], $name, $body );// handle the space this way in case of missing name, so you dont have the famous "Hello ,"
		$body = add_markup_to_emails( $body, $code, $link );
		$sent = wp_mail( $email, $subject, $body, 'Content-Type: text/html;' );
		if ( $sent ) $return = "Check your email for the auto-login link";
	}
	if ( ! $sent ) {
		return "problem sending";
	}
	set_transient( "mnml2fa_{$key}", $login_data, 300 );
	// if ( $code ) $return .= "<br>or enter the security code:";
	return $return;
}


function get_link_button() {

	$settings = (object) get_option( 'mnml2fa', array() );

	// $key = bin2hex( random_bytes(16) );// 2nd code hidden in the code form, to make it even more impossible
	// echo "<div style='display:flex;align-items:center'><div style='height:1px;width:50%;background:currentColor'></div><div style='padding:1ex'>OR</div><div style='height:1px;width:50%;background:currentColor'></div></div>";
	?>
	<p>
		<label for="mnml2falog">Email Address<?php if ( function_exists(__NAMESPACE__.'\send_via_twilio') ) echo " or Phone Number"; ?></label>
		<input type="text" name="mnml2falog" id="mnml2falog" class="input" size="20" autocapitalize="off" autocomplete="email<?php if ( function_exists(__NAMESPACE__.'\send_via_twilio') ) echo " tel"; ?>" required="required" />
	</p>
	<input type="hidden" name="mnml2fak" id=mnml2fak />
	
	<div id="mnml2fa-code-sent">
		<p><span>Check your device for the auto-login link</span>
		<?php if ( !empty($settings->code_with_magic_link) ) : ?>
		<br>or enter the security code:
		<input type="number" name="mnml2fac" id="mnml2fac" class="input" size="20" autocomplete="one-time-code"></p>
		<button id=mnml-code-submit class="button button-primary button-large" formnovalidate>Submit Code</button>
		<?php endif; ?>
	</div>

	<button id=mnml-magic-link formnovalidate>Get Sign-on Link</button>
	<script>
	//document.querySelector('#mnml-magic-link').closest('form').querySelectorAll('[required]').forEach(e=>{if(e.id!='mnml2falog')e.required=0});
	document.querySelector('#mnml2fak').value=Math.random();
	document.querySelector('form').addEventListener( 'submit', e => {
		var f = new FormData(e.target);
		if ( ! f.get('mnml2fac') ) {
			e.preventDefault();
			if ( f.get('mnml2falog') ) {
				fetch('/wp-json/mnml2fa/v1/sendlink',{method:'POST',body: f }).then(r=>{return r.json()}).then(r=>{
					e.target.classList.add('link-sent');
					// e.target.action='';
					// document.querySelector('#mnml2fa-code-sent p').insertAdjacentHTML('afterBegin',r);
					document.querySelector('#mnml2fa-code-sent span').textContent=r;
					document.querySelector('#mnml2fac').focus();
				});
			}
		}
		// var log = document.querySelector('[name=log]').value;
		// if ( log )
		// fetch('/wp-json/mnml2fa/v1/sendlink',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"log":"'+log+'"}'}).then(r=>{return r.json()}).then(r=>{e.target.innerText=r});
	});</script>
	<?php

}
 
function signon_link_styles() {
	// first line of selectors is for Formidable's login form
	?><style>
	.login-password, .login-username, form.link-sent .login-remember,
	label[for=user_login], input#user_login,
	[name=wp-submit],
	.user-pass-wrap,
	#mnml2fa-code-sent,
	form.link-sent #mnml-magic-link,
	form.link-sent #mnml2falog,
	form.link-sent .forgetmenot,
	form.link-sent [for=mnml2falog] {
		display: none !important;
	}
	form.link-sent #mnml2fa-code-sent {
		display: unset !important;
	}
	</style><?php
}


function authenticate( $user, $user_name ) {

	// only run if $user is a user object, which means user/pass were accepted
	if ( $user instanceof \WP_User ) {
		// is user that needs 2fa

		if ( ! $user->has_cap('administrator') ) return $user;
		
		// if ( $_SERVER['REMOTE_ADDR'] === 'IPADDRESS' ) return $user;
		
		$settings = (object) get_option( 'mnml2fa', array() );
		
		$code = sprintf( "%06s", random_int(0, 999999) );// six digit code
		// $key = bin2hex( random_bytes(16) );// 2nd code hidden in the code form, to make it even more impossible
		$key = random_int((int)1e16, (int)1e20);
		
		$sent = false;
		if ( function_exists(__NAMESPACE__.'\send_via_twilio') ) {

			$phone = apply_filters( 'mnml2fa_get_tele_by_user', null, $user );
			if ( $phone === null ) {
				$meta_key = $settings->telephone_user_meta ?? 'mnml2fano';
				$phone = get_user_meta( $user->ID, $meta_key, true );
			}
			if ( $phone ) $sent = send_via_twilio( $phone, $code );
			if ( $sent ) $sent = 'phone';
		}
		if ( ! $sent ) {

			$email = $user->user_email;// $user->get('user_email')
			if ( ! $email ) {
				error_log("no email in mnml2fa");
				exit;
			}
			
			$subject = $settings->code_email_subject ?? "Your security code is %code%";
			$subject = str_ireplace( '%code%', $code, $subject );

			$body = $settings->link_email_body ?? "Hello %name%, here is the security code you requested";
			$name = " ". $user->first_name ?? " ". $user->display_name ?? "";
			$body = str_ireplace( [" %name%", "%name%" ], $name, $body );// handle the space this way in case of missing name, so you dont have the famous "Hello ,"

			$body = add_markup_to_emails( $body, $code );

			$sent = wp_mail( $email, $subject, $body, 'Content-Type: text/html;' );
			if ( $sent ) $sent = 'email';
		}

		if ( $sent ) {

			$login_data = [ 'id' => $user->ID ];
			set_transient( "mnml2fa_{$code}{$key}", $login_data, 300 );
			$login_url = site_url( 'wp-login.php', 'login' );
			if ( ! empty( $_REQUEST['redirect_to'] ) ) $login_url = add_query_arg( 'redirect_to', urlencode( $_REQUEST['redirect_to'] ), $login_url );
			$login_url = add_query_arg( ['action' => '2fa', 'd' => $sent, 'rm' => !empty($_REQUEST['rememberme']), 'k' => $key ], $login_url );
			wp_redirect( $login_url );
			exit;
		} else {
			error_log("not sent");
		}
	}
	elseif ( !empty( $_POST['mnml2fac'] ) && !empty( $_POST['mnml2fak'] ) )
	{
		$code_key = filter_var( $_POST['mnml2fak'], FILTER_SANITIZE_NUMBER_INT );
		if ( strlen( $code_key ) < 9 ) return "code key was weird";

		// error_log( var_export( $_REQUEST, 1 ) );

		$settings = (object) get_option( 'mnml2fa', array() );
		
		$login_data = get_transient("mnml2fa_{$_POST['mnml2fac']}{$code_key}");
		$login_data = (object) $login_data;
		
		if ( empty($login_data->id) ) {
			error_log("transient did not exist for code {$_POST['mnml2fac']}");
			return new \WP_Error( 'invalid_code', 'The security code was invalid or expired.  Please try again.' );
		} else {
			$user = get_user_by( 'id', $login_data->id );
			// error_log( "logged in user {$user->user_login} from IP {$_SERVER['REMOTE_ADDR']}");
			if ( empty($settings->no_login_alerts ) ) {
				$message = "New login from IP {$_SERVER['REMOTE_ADDR']}";
				wp_mail( $user->user_email, $message, $message . "\n\nuser agent: {$_SERVER['HTTP_USER_AGENT']}" );
			}
		}
	}
	elseif ( !empty( $_GET['tfal'] ) )// Magic Link
	{
		$settings = (object) get_option( 'mnml2fa', array() );
		
		$login_data = get_transient("mnml2fa_{$_GET['tfal']}");
		$login_data = (object) $login_data;
		
		
		if ( empty($login_data->id) ) {
			error_log("transient did not exist for code key {$_GET['tfal']}");
			return new \WP_Error( 'invalid_link', 'The link was expired.  Please try again.' );
		} else {
			$user = get_user_by( 'id', $login_data->id );
			// error_log( "logged in user {$user->user_login} from IP {$_SERVER['REMOTE_ADDR']}");
			if ( empty($settings->no_login_alerts ) ) {
				$message = "New login from IP {$_SERVER['REMOTE_ADDR']}";
				wp_mail( $user->user_email, $message, $message . "\n\nuser agent: {$_SERVER['HTTP_USER_AGENT']}" );
			}
		}
	}
	return $user;
}


function login_form(){

	$redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : home_url();// this should always be set though see https://github.com/WordPress/WordPress/blob/c6028577a462f235da67e5d3dcf1dc42f9a96669/wp-login.php#L1226
	$rememberme = ! empty( $_GET['rm'] );

	$key = filter_input( INPUT_GET, 'k', FILTER_SANITIZE_STRING );
	if ( ! $key ) {
		error_log("something's wrong, there's no key for 2fa");
		wp_safe_redirect( 'wp-login.php' );
		exit;
	}

	$device = filter_input( INPUT_GET, 'd', FILTER_SANITIZE_STRING ) ?: 'security device';
	login_header( "New Device Authentication", "<p class=message>A code was just sent to your {$device}. Please enter it to continue.</p>" );
	?>
	<style>#mnml2fac::-webkit-inner-spin-button{display:none}</style>
	<form name=2fa id=2fa action="<?php echo esc_url( network_site_url( 'wp-login.php', 'login_post' ) ); ?>" method=post>
		<input type=hidden name=mnml2fak value="<?php echo $key; ?>" />
		<input type=hidden name=redirect_to value="<?php echo sanitize_url( $redirect_to ); ?>" />
		<p><input type=number name=mnml2fac id=mnml2fac class=input size=20 autocomplete=one-time-code autofocus />
		<p class=forgetmenot><input name=rememberme type=checkbox id=rememberme value=forever <?php checked( $rememberme ); ?> /> <label for=rememberme><?php esc_html_e( 'Remember Me' ); ?></label>
		<p class=submit><input type=submit name=wp-submit id=wp-submit class="button button-primary button-large" value=Submit />
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

// add_filter( 'plugin_action_links', __NAMESPACE__.'\add_settings_link', 10, 2 );
function add_settings_link( $links, $file ) {
	if ( $file === 'mnml-2fa/mnml-2fa.php' && current_user_can( 'manage_options' ) ) {
		$url = admin_url( 'options-general.php?page=mnml2fa' );
		$links = (array) $links;// Prevent warnings in PHP 7.0+ when a plugin uses this filter incorrectly.
		$links[] = sprintf( '<a href="%s">%s</a>', $url, 'Settings' );
	}
	return $links;
}

function settings_page() {

	$fields = array_fill_keys([
		'type',
		'no_login_alerts',
		'code_settings',
		'code_email_subject',
		'code_email_body',
		'code_sms_message',
		'code_settings_end',
		'link_settings',
		'code_with_magic_link',
		'link_email_subject',
		'link_email_body',
		'link_button_text','link_button_color',
		'link_sms_message',
		'link_settings_end',
		'twilio_account_sid', 'twilio_api_sid', 'twilio_api_secret', 'twilio_messaging_service_sid', 'twilio_from',
		'telephone_user_meta',
	],
	[ 'type' => 'text' ]);// default

	$fields['code_settings'] = ['type' => 'section', 'show' => ['type' => 'code'] ];
	$fields['code_settings_end'] = ['type' => 'section_end'];
	$fields['link_settings'] = ['type' => 'section', 'show' => ['type' => 'link'] ];
	$fields['link_settings_end'] = ['type' => 'section_end'];

	$fields['type'] = [ 'type' => 'radio', 'options' => ['code','link']];
	$fields['code_with_magic_link']['type'] = 'checkbox';
	$fields['code_email_body']['type'] = $fields['link_email_body']['type'] = $fields['code_sms_message']['type'] = $fields['link_sms_message']['type'] = 'textarea';
	$fields['code_email_body']['placeholder'] = "Hello %name%, here is the security code you requested";
	$fields['code_email_subject']['placeholder'] = 'Your security code is %code%';
	$fields['code_sms_message']['placeholder'] = 'Your security code is %code%';
	$fields['link_email_subject']['placeholder'] = 'Your sign-in link';
	$fields['link_email_body']['placeholder'] = 'Hello %name%, here is the sign-in link you requested';
	$fields['link_button_text']['placeholder'] = 'Sign In';
	$fields['link_button_color']['placeholder'] = '#777777';
	$fields['link_sms_message']['placeholder'] = 'Click to sign in: %link%';
	$fields['no_login_alerts']['type'] = 'checkbox';
	$fields['no_login_alerts']['desc'] = 'Disable new login alert emails';
	$fields['twilio_account_sid']['before'] = "<h3>Twilio settings for SMS codes instead of email</h3>";
	$fields['twilio_account_sid']['placeholder'] = 'AC...';
	$fields['twilio_messaging_service_sid']['placeholder'] = 'MG...';


	/**
	 *  Build Settings Page using framework in settings_page.php
	 **/
	$options = [ 'mnml2fa' => $fields ];// can add additional options groups to save as their own array in the options table
	$endpoint = rest_url(__NAMESPACE__.'/v1/settings');
	$title = "2FA Settings";
	require( __DIR__.'/settings-page.php' );// needs $options, $endpoint, $title
}


function add_markup_to_emails( $message, $code='', $link='' ) {

	$settings = (object) get_option( 'mnml2fa', array() );

	if ( strpos( $message, "<p" ) === false && strpos( $message, "<br" ) === false ) {
		$message = str_replace( "\n", "<br>",  $message );
	}
	
	$concern = "If you did not just try to login, someone knows or has guessed your ";
	$concern .= $link ? "login, but they cannot login without this link." : "password, but they cannot login without this code.";

	// if ( substr( $message, 0, 9 ) === "<!DOCTYPE" ) {
	// 	error_log("matched <!DOCTYPE");
	// 	return $message;
	// } elseif ( strpos( substr( $message, 0, 200 ), "<html" ) ) {
	// 	error_log("matched <html");
	// 	return $message;
	// }

	ob_start();
	?>
	<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
	<meta charset="UTF-8">
	<meta content="width=device-width, initial-scale=1" name="viewport">
	<meta name="x-apple-disable-message-reformatting">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
<!--[if gte mso 9]><xml>
	<o:OfficeDocumentSettings>
	<o:AllowPNG/>
	<o:PixelsPerInch>96</o:PixelsPerInch>
	</o:OfficeDocumentSettings>
</xml><![endif]-->
<style type="text/css">
	@media only screen and (max-width: 600px) {
		table {
			width: 100% !important;
		}
	}
</style>
</head>
<body style="width:100%;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;font-family:sans-serif;line-height:1.5;padding:0;margin:0;background-color:#F6F6F6;">
	<table style="border-collapse:collapse;border-spacing:0px;width:100%;height:100%;background-color:#F6F6F6" cellspacing="0" cellpadding="0">
		<tr style="border-collapse:collapse;">
			<td style="padding:24px;" align="center">
				<table style="background-color:#ffffff;width:600px;" cellspacing="0" cellpadding="0">
					<tr style="border-collapse:collapse;">
						<td style="padding:24px;text-align:center;font-size:16px">
							<?php
							echo $message;
							if ( $link ) {
								$button_text = $settings->link_button_text ?? "Sign In";
								$button_color = $settings->link_button_color ?? "#777";
								echo "<p style='margin:36px;'><a href='{$link}' style='background:{$button_color};padding:12px 16px;color:#fff;text-decoration:none;font-weight:700;'>{$button_text}</a></p>";
								if ( $code ) {
									echo "<p>or enter this code on the open login page:</p>";
								}
							}
							if ( $code ) {
								echo "<p style='font-size:36px;letter-spacing:6px;margin:24px;'>{$code}</p>";
							}
							echo "<p style='font-size:13px;'>{$concern}</p>";
							?>
						</td>
					</tr>
				</table>
			</td>
		</tr>
		<tr style="border-collapse:collapse;">
			<td style="text-align:center;padding: 0 0 48px;">
				<p><a href="<?php echo get_option('home'); ?>"><?php echo get_option('blogname'); ?></a></p>
			</td>
		</tr>
	</table>
</body>
</html>
<?php

	return ob_get_clean();
}

/**
 * generate random strings
 */
function random( $len=8, $prefix='' ) {
	$chars = array_merge( range('0','9'), range('A','Z'), range('a','z') );
	for ($i=0; $i < $len; $i++) $prefix .= $chars[mt_rand(0, count($chars)-1)];
	return $prefix;
}