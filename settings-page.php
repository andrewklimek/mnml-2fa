<?php
/**
 * This is my settings page framework
 * Should be included with variables $options, $endpoint, $title (optional)
 */

if ( empty( $options ) || empty( $endpoint ) ) return;

// XMLHttpRequest version:
// $nonce = "x.setRequestHeader('X-WP-Nonce','". wp_create_nonce('wp_rest') ."')";
// <form onsubmit="event.preventDefault();var t=this,b=t.querySelector('.button-primary'),x=new XMLHttpRequest;x.open('POST','<php echo $url.'settings'; >'),<php echo $nonce; >,x.onload=function(){b.innerText=JSON.parse(x.response);t.addEventListener('input',function(){b.innerText='Save Changes'})},x.send(new FormData(t))">
$nonce = "headers:{'X-WP-Nonce':'". wp_create_nonce('wp_rest') ."'}";

echo "<div class=wrap>";
if ( !empty( $title ) ) echo "<h1>$title</h1>";
echo '<form onsubmit="';
echo "event.preventDefault();var t=this,b=t.querySelector('.button-primary');fetch('{$endpoint}',{method:'POST',{$nonce},body:new FormData(this),})";
echo ".then(r=>{return r.json()}).then(r=>{b.innerText=r;t.addEventListener('input',function(){b.innerText='Save Changes'})})";
echo '">';

$values = [];
foreach ( $options as $g => $fields ) {
	$values += get_option( $g, [] );
}

$script = '';
echo '<table class=form-table>';
foreach ( $options as $g => $fields ) {
	// $values = get_option($g);
	echo "<input type=hidden name='{$g}[x]' value=1>";// hidden field to make sure things still update if all options are empty (defaults)
	foreach ( $fields as $k => $f ) {
		if ( !empty( $f['before'] ) ) echo "<tr><th>" . $f['before'];
		$v = isset( $values[$k] ) ? $values[$k] : '';
		$l = isset( $f['label'] ) ? $f['label'] : str_replace( '_', ' ', $k );
		$ph = !empty( $f['placeholder'] ) ? $f['placeholder'] : '';
		$size = !empty( $f['size'] ) ? $f['size'] : 'regular';
		$hide = '';
		if ( !empty( $f['show'] ) ) {
			if ( is_string( $f['show'] ) ) $f['show'] = [ $f['show'] => 'any' ];
			foreach( $f['show'] as $target => $cond ) {
				$hide = " style='display:none'";
				$script .= "\ndocument.querySelector('#tr-{$target}').addEventListener('change', function(e){";
				if ( $cond === 'any' ) {
					$script .= "if( e.target.checked !== false && e.target.value )";
					if ( !empty( $values[$target] ) ) $hide = "";
				}
				elseif ( $cond === 'empty' ) {
					$script .= "if( e.target.checked === false || !e.target.value )";
					if ( empty( $values[$target] ) ) $hide = "";
				}
				else {
					$script .= "if( !!~['". implode( "','", (array) $cond ) ."'].indexOf(e.target.value) && e.target.checked!==false)";
					if ( !empty( $values[$target] ) && in_array( $values[$target], (array) $cond ) ) $hide = "";
				}
				$script .= "{document.querySelector('#tr-{$k}').style.display='revert'}";
				$script .= "else{document.querySelector('#tr-{$k}').style.display='none'}";
				$script .= "});";
			}
		}
		if ( empty( $f['type'] ) ) $f['type'] = !empty( $f['options'] ) ? 'radio' : 'checkbox';// checkbox is default

		if ( $f['type'] === 'section' ) { echo "<tbody id='tr-{$k}' {$hide}>"; continue; }
		elseif ( $f['type'] === 'section_end' ) { echo "</tbody>"; continue; }
		else echo "<tr id=tr-{$k} {$hide}><th>";
		
		if ( !empty( $f['callback'] ) && function_exists( __NAMESPACE__ .'\\'. $f['callback'] ) ) {
			echo "<label for='{$g}-{$k}'>{$l}</label><td>";
			call_user_func( __NAMESPACE__ .'\\'. $f['callback'], $g, $k, $v, $f );
		} else {
			switch ( $f['type'] ) {
				case 'textarea':
					echo "<label for='{$g}-{$k}'>{$l}</label><td><textarea id='{$g}-{$k}' name='{$g}[{$k}]' placeholder='{$ph}' rows=8 class={$size}-text>{$v}</textarea>";
					break;
				case 'code':
					echo "<label for='{$g}-{$k}'>{$l}</label><td><textarea id='{$g}-{$k}' name='{$g}[{$k}]' placeholder='{$ph}' rows=8 class='large-text code'>{$v}</textarea>";
					break;
				case 'number':
					$size = !empty( $f['size'] ) ? $f['size'] : 'small';
					echo "<label for='{$g}-{$k}'>{$l}</label><td><input id='{$g}-{$k}' name='{$g}[{$k}]' placeholder='{$ph}' value='{$v}' class={$size}-text type=number>";
					break;
				case 'radio':
					if ( !empty( $f['options'] ) && is_array( $f['options'] ) ) {
						echo "{$l}<td>";
						foreach ( $f['options'] as $ov => $ol ) {
							if ( ! is_string( $ov ) ) $ov = $ol;
							echo "<label><input name='{$g}[{$k}]' value='{$ov}'"; if ( $v == $ov ) echo " checked"; echo " type=radio>{$ol}</label> ";
						}
					}
					break;
				case 'select':
					if ( !empty( $f['options'] ) && is_array( $f['options'] ) ) {
						echo "<label for='{$g}-{$k}'>{$l}</label><td><select id='{$g}-{$k}' name='{$g}[{$k}]'>";
						echo "<option value=''></option>";// placeholder
						foreach ( $f['options'] as $key => $value ) {
							echo "<option value='{$key}'" . selected( $v, $key, false ) . ">{$value}</option>";
						}
						echo "</select>";
					}
					break;
				case 'text':
					echo "<label for='{$g}-{$k}'>{$l}</label><td><input id='{$g}-{$k}' name='{$g}[{$k}]' placeholder='{$ph}' value='{$v}' class={$size}-text>";
					break;
				case 'checkbox':
				default:
					echo "<label for='{$g}-{$k}'>{$l}</label><td><input id='{$g}-{$k}' name='{$g}[{$k}]'"; if ( $v ) echo " checked"; echo " type=checkbox >";
					break;
			}
		}
		if ( !empty( $f['desc'] ) ) echo "&nbsp; " . $f['desc'];
	}
}
if ( $script ) echo "<script>$script</script>";
echo "</table>";
echo "<div style='position:fixed;bottom:0;left:0;right:0;padding:16px 0 16px 180px;z-index:1;background:#333b41'><button class=button-primary>Save Changes</button></div>";
echo "</form></div>";