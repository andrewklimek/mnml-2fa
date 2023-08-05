<?php


function mnml2fa_send_via_twilio( $phone, $code ) {

	$settings = get_option( 'mnml2fa' );

	// API keys - does it have to be type "main" ?
	$sid = $settings['twilio_account_sid'];// Account SID
	$user = $settings['twilio_api_sid'];// API SID
	$pass = $settings['twilio_api_secret'];// API Secret
	$from = $settings['twilio_from'];// from can just be a text string somehow... not in the US though.  See https://www.twilio.com/docs/sms/send-messages#use-an-alphanumeric-sender-id
	$to = "+" . $phone;
	$body = "Your security code is $code";// default
	if ( !empty($settings['sms_message']) ) {
		$body = str_ireplace( '%code%', $code, $settings['email_body'], $n );
		if (0===$n) $body .= " $code";// add the code on the end if they didn't use the %code% merge tag in their message
	}

	// https://www.php.net/manual/en/function.curl-setopt.php
	// https://github.com/twilio/twilio-php/blob/main/src/Twilio/Http/CurlClient.php
	$options = array(
		CURLOPT_URL => "https://api.twilio.com/2010-04-01/Accounts/$sid/Messages.json",
		CURLOPT_RETURNTRANSFER => true,
		// CURLOPT_HEADER => true,// helped with debugging
		CURLOPT_TIMEOUT => 60,
		CURLOPT_POST => true,
		CURLOPT_HTTPHEADER => ['Authorization: Basic ' . base64_encode("$user:$pass")],
		CURLOPT_POSTFIELDS => http_build_query([ 'From' => $from, 'To' => $to, 'Body' => $body ])
	);
	$ch = curl_init();
	curl_setopt_array($ch, $options);
	$result = curl_exec($ch);
	curl_close($ch);
	$result = json_decode($result);

	if ( empty( $result->date_created ) || !empty( $result->code ) ) {
		error_log("twilio failed: " . var_export($result,true));
		return false;
	}
	return true;
}


/**
 * phone number field in user profile
 */
add_action('show_user_profile','mnml2fa_usermeta_form_field');
add_action('edit_user_profile','mnml2fa_usermeta_form_field');
add_action('personal_options_update','mnml2fa_usermeta_form_field_update');
add_action('edit_user_profile_update','mnml2fa_usermeta_form_field_update');
function mnml2fa_usermeta_form_field( $user ) {
	?>
	<h3>2FA Settings</h3>
	<table class="form-table">
		<tr>
			<th><label for="mnml2fano">2FA Phone Number</label></th>
			<td>
				+<input class="regular-text ltr" id="mnml2fano" name="mnml2fano" value="<?php echo esc_attr( get_user_meta( $user->ID, 'mnml2fano', true ) ) ?>">
				<p class="description">Include country code</p>
	</table>
	<?php
}
function mnml2fa_usermeta_form_field_update( $user_id ) {
	if ( ! current_user_can( 'edit_user', $user_id ) ) return false;
	// $number = ltrim( filter_input( INPUT_POST, "mnml2fano", FILTER_SANITIZE_NUMBER_INT ), '+' );
	if ( isset( $_POST['mnml2fano'] ) ) {// not sure if its ever not set
		return update_user_meta( $user_id, 'mnml2fano', preg_replace('/\D/', '', $_POST['mnml2fano'] ) );
	}
	return;
}
