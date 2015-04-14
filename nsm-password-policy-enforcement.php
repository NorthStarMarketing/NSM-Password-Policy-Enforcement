<?php
/**
 * Plugin Name: NSM Password Policy Enforcement
 * Plugin URI: http://northstarmarketing.com
 * Description: A WordPress plugin to enforce strong user passwords. Based off of work previously done by <a href="http://www.webtipblog.com/force-password-complexity-requirements-wordpress/" target="_blank">Joe Sexton</a>.
 * Version: 0.1
 * Author: North Star Marketing
 * Author URI: http://northstarmarketing.com
 * License: GPL2
 */ 

include_once('interface.php');

add_action( 'user_profile_update_errors', 'validateProfileUpdate', 10, 3 );
add_filter( 'registration_errors', 'validateRegistration', 10, 3 );
add_action( 'validate_password_reset', 'validatePasswordReset', 10, 2 );
 
 
 
/**
 * validate profile update
 *
 * @author  Joe Sexton <joe.@webtipblog.com>
 * @param   WP_Error $errors
 * @param   boolean $update
 * @param   object $user raw user object not a WP_User
 */
function validateProfileUpdate( WP_Error &$errors, $update, &$user ) {
 
    return validateComplexPassword( $errors );
}
 
 
/**
 * validate registration
 *
 * @author  Joe Sexton <joe.@webtipblog.com>
 * @param   WP_Error $errors
 * @param   string $sanitized_user_login
 * @param   string $user_email
 * @return  WP_Error
 */
function validateRegistration( WP_Error &$errors, $sanitized_user_login, $user_email ) {
 
    return validateComplexPassword( $errors );
}
 
/**
 * validate password reset
 *
 * @author  Joe Sexton <joe.@webtipblog.com>
 * @param   WP_Error $errors
 * @param   stdClass $userData
 * @return  WP_Error
 */
function validatePasswordReset( WP_Error $errors, $userData ) {
 
    return validateComplexPassword( $errors );
}
 
/**
 * validate complex password
 *
 * @author  Joe Sexton <joe.@webtipblog.com>
 * @param   WP_Error $errors
 * @param   stdClass $userData
 * @return  WP_Error
 */
function validateComplexPassword( $errors ) {
 
    $password = ( isset( $_POST[ 'pass1' ] ) && trim( $_POST[ 'pass1' ] ) ) ? $_POST[ 'pass1' ] : null;
 
    // no password or already has password error
    if ( empty( $password ) || ( $errors->get_error_data( 'pass' ) ) )
        return $errors;
    
    $pass = isStrongPassword( $password );
    
    // validate
    if ( ! $pass['length'] )
    	$errors->add( 'pass', '<strong>ERROR</strong>: Your password must contain at least eight (8) characters.' );
    	
    if ( ! $pass['num'] )
    	$errors->add( 'pass', '<strong>ERROR</strong>: Your password must contain at least one (1) number.' );
    	
    if ( ! $pass['alpha'] )
    	$errors->add( 'pass', '<strong>ERROR</strong>: Your password must contain at least one (1) letter.' );
    	
    if ( ! $pass['upper'] )
    	$errors->add( 'pass', '<strong>ERROR</strong>: Your password must contain at least one (1) uppercase letter.' );
    	
    if ( ! $pass['lower'] )
    	$errors->add( 'pass', '<strong>ERROR</strong>: Your password must contain at least one (1) lowercase letter.' );
    	
    if ( ! $pass['special'] )
    	$errors->add( 'pass', '<strong>ERROR</strong>: Your password must contain at least one (1) special character.' );
    	
    return $errors;
    
}
 
/**
 * isStrongPassword
 *
 * @author  Joe Sexton <joe.@webtipblog.com>
 * @param   string $password
 * @return  boolean
 */
function isStrongPassword( $password ) {
 
 	// check if password meets length criteria (at least 8 characters)
 	if ( strlen( $password ) >= 8 ) {
	 	$pass['length'] = true;
 	} else {
	 	$pass['length'] = false;
 	}
 	
 	// check if password contains numbers
 	if ( preg_match( '/[0-9]/', $password ) ) {
	 	$pass['num'] = true;
 	} else {
	 	$pass['num'] = false;
 	}
 	
 	// check if password contains letters
 	if ( preg_match( '/[a-zA-Z]/', $password ) ) {
	 	$pass['alpha'] = true;
 	} else {
	 	$pass['alpha'] = false;
 	}
 	
 	// check if password has upper case
 	if ( preg_match( '/[A-Z]/', $password ) ) {
	 	$pass['upper'] = true;
 	} else {
	 	$pass['upper'] = false;
 	}
 	
 	// check if password has lower case
 	if ( preg_match( '/[a-z]/', $password ) ) {
	 	$pass['lower'] = true;
 	} else {
	 	$pass['lower'] = false;
 	}
 	
 	// check if password has a special character
 	if ( preg_match('/[!?@\#\$%\^&\*\(\)\-\=\_\+]/', $password ) ) {
	 	$pass['special'] = true;
 	} else {
	 	$pass['special'] = false;
 	}
 	
 	return $pass;
 
}