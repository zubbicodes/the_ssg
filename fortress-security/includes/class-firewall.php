<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Fortress_Firewall {

	private static $instance;

	public static function instance() : self {
		if ( ! self::$instance ) self::$instance = new self();
		return self::$instance;
	}

	private function __construct() {}

	/* ── Bootstrap ────────────────────────────────────────────────────── */
	public function init() {
		if ( ! get_option( 'fortress_enabled' ) ) return;

		// Firewall blacklist — block on every request, very early
		if ( get_option( 'fortress_firewall_enabled', 1 ) ) {
			add_action( 'init', [ $this, 'enforce_ip_blacklist' ], 0 );
		}

		// IP whitelist runs very early (init priority 1)
		add_action( 'init', [ $this, 'enforce_ip_whitelist' ], 1 );

		// Username whitelist — hook into authentication
		if ( get_option( 'fortress_username_whitelist_enabled', 0 ) ) {
			add_filter( 'wp_authenticate_user', [ $this, 'enforce_username_whitelist' ], 1, 2 );
			add_action( 'wp_login_failed',      [ $this, 'on_unauthorized_username' ], 1, 1 );
		}

		// Block xmlrpc
		if ( get_option( 'fortress_block_xmlrpc' ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_action( 'init', [ $this, 'block_xmlrpc_direct' ], 1 );
		}

		// Registration lockdown
		if ( get_option( 'fortress_reg_lock' ) ) {
			add_filter( 'option_users_can_register', '__return_zero' );
			add_action( 'init', [ $this, 'block_registration_request' ], 1 );
			add_filter( 'registration_errors', [ $this, 'registration_locked_error' ], 99, 3 );
			add_action( 'user_register', [ $this, 'delete_unauthorized_user' ], 99 );
		}
	}

	/* ── IP blacklist — block on EVERY request ───────────────────────── */
	public function enforce_ip_blacklist() {
		$ip  = Fortress_Logger::get_ip();
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		if ( ! Fortress_DB::is_ip_blacklisted( $ip ) ) return;

		Fortress_DB::insert_log( [
			'ip_address'     => $ip,
			'request_method' => isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET',
			'request_uri'    => substr( $uri, 0, 2048 ),
			'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 512 ) : '',
			'is_suspicious'  => 1,
			'threat_type'    => 'firewall_blacklist',
			'threat_score'   => 100,
			'blocked'        => 1,
		] );

		Fortress_Discord::alert_blocked( $ip, $uri, 'Firewall: IP is blacklisted' );

		http_response_code( 403 );
		nocache_headers();
		wp_die(
			'<h1>403 — Access Denied</h1><p>Your IP address has been blocked by the site firewall.</p>',
			'Access Denied',
			[ 'response' => 403, 'back_link' => false ]
		);
	}

	/* ── IP whitelist for wp-admin & wp-login ─────────────────────────── */
	public function enforce_ip_whitelist() {
		if ( ! get_option( 'fortress_ip_whitelist_enabled' ) ) return;

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$is_admin_req = (
			strpos( $uri, '/wp-admin' ) !== false ||
			strpos( $uri, 'wp-login.php' ) !== false
		);

		if ( ! $is_admin_req ) return;

		$ip    = Fortress_Logger::get_ip();
		$token = get_option( 'fortress_emergency_token', '' );

		// Emergency bypass via ?fortress_token=<token>
		if ( ! empty( $token ) && isset( $_GET['fortress_token'] ) && $_GET['fortress_token'] === $token ) {
			// Allow and optionally auto-add the IP
			return;
		}

		if ( Fortress_DB::is_ip_whitelisted( $ip ) ) return;

		// Block — log it, notify Discord, then die
		$redirect = get_option( 'fortress_whitelist_redirect', '' );

		Fortress_DB::insert_log( [
			'ip_address'     => $ip,
			'request_method' => isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET',
			'request_uri'    => substr( $uri, 0, 2048 ),
			'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 512 ) : '',
			'is_suspicious'  => 1,
			'threat_type'    => 'admin_ip_blocked',
			'threat_score'   => 60,
			'blocked'        => 1,
		] );

		Fortress_Discord::alert_blocked( $ip, $uri, 'IP not in admin whitelist' );

		if ( $redirect ) {
			wp_safe_redirect( $redirect );
			exit;
		}

		http_response_code( 403 );
		nocache_headers();
		wp_die(
			'<h1>403 — Access Denied</h1><p>Your IP address is not authorised to access this area.</p>',
			'Access Denied',
			[ 'response' => 403, 'back_link' => false ]
		);
	}

	/* ── Block xmlrpc.php direct requests ─────────────────────────────── */
	public function block_xmlrpc_direct() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		if ( strpos( $uri, 'xmlrpc.php' ) === false ) return;

		$ip = Fortress_Logger::get_ip();
		Fortress_DB::insert_log( [
			'ip_address'     => $ip,
			'request_method' => isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET',
			'request_uri'    => substr( $uri, 0, 2048 ),
			'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 512 ) : '',
			'is_suspicious'  => 1,
			'threat_type'    => 'xmlrpc_access',
			'threat_score'   => 40,
			'blocked'        => 1,
		] );

		http_response_code( 403 );
		die( '<?xml version="1.0"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>403</int></value></member><member><name>faultString</name><value><string>XML-RPC is disabled.</string></value></member></struct></value></fault></methodResponse>' );
	}

	/* ── Block registration via URL ───────────────────────────────────── */
	public function block_registration_request() {
		if (
			isset( $_GET['action'] ) &&
			in_array( $_GET['action'], [ 'register', 'signup' ], true ) &&
			isset( $_SERVER['REQUEST_URI'] ) &&
			strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false
		) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
	}

	/* ── Registration error override ─────────────────────────────────── */
	public function registration_locked_error( $errors, $sanitized_user_login, $user_email ) {
		$errors->add( 'registrations_disabled', __( 'User registration is currently disabled.', 'fortress-security' ) );
		return $errors;
	}

	/* ── Delete any user created despite the lock (API/REST bypass) ───── */
	public function delete_unauthorized_user( $user_id ) {
		// Only fire on front-end/REST registrations — not admin-created users
		if ( is_admin() ) return;
		if ( current_user_can( 'create_users' ) ) return;

		$ip = Fortress_Logger::get_ip();
		Fortress_DB::insert_log( [
			'ip_address'    => $ip,
			'request_method'=> 'POST',
			'request_uri'   => '/wp-login.php',
			'is_suspicious' => 1,
			'threat_type'   => 'unauthorized_registration',
			'threat_score'  => 70,
			'blocked'       => 1,
		] );

		Fortress_Discord::alert_blocked( $ip, '/register', 'Unauthorized user registration attempt — user deleted' );
		require_once ABSPATH . 'wp-admin/includes/user.php';
		wp_delete_user( $user_id );
	}
	/* ── Username whitelist enforcement ─────────────────────────────────── */
	/**
	 * Fires on wp_authenticate_user filter. If the username whitelist is active
	 * and the attempted username is NOT in the list, we return a WP_Error so
	 * WordPress rejects the login AND our on_unauthorized_username() logger fires.
	 * We also immediately blacklist the attacker's IP.
	 */
	public function enforce_username_whitelist( $user, $password ) {
		if ( is_wp_error( $user ) ) return $user;

		// If the whitelist has no entries yet, skip enforcement to avoid lockout
		if ( Fortress_DB::username_whitelist_count() === 0 ) return $user;

		if ( Fortress_DB::is_username_whitelisted( $user->user_login ) ) return $user;

		// Store the bad username in a transient so on_unauthorized_username() can log it
		$ip = Fortress_Logger::get_ip();
		set_transient( 'fortress_bad_username_' . md5( $ip ), $user->user_login, 30 );

		// Auto-blacklist the attacker's IP
		if ( ! Fortress_DB::is_ip_blacklisted( $ip ) ) {
			Fortress_DB::add_to_blacklist(
				$ip,
				'Auto-blocked: disallowed username "' . esc_attr( $user->user_login ) . '"',
				0,
				null
			);
		}

		// Log immediately (so username appears in logs)
		Fortress_DB::insert_log( [
			'ip_address'         => $ip,
			'request_method'     => 'POST',
			'request_uri'        => '/wp-login.php',
			'user_agent'         => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 512 ) : '',
			'is_suspicious'      => 1,
			'threat_type'        => 'username_not_whitelisted',
			'threat_score'       => 90,
			'blocked'            => 1,
			'attempted_username' => $user->user_login,
		] );

		Fortress_Discord::alert_blocked( $ip, '/wp-login.php', 'Username not whitelisted: ' . $user->user_login );

		return new WP_Error(
			'fortress_username_blocked',
			__( '<strong>Error</strong>: Login attempt blocked by security firewall.', 'fortress-security' )
		);
	}

	/**
	 * Catches the wp_login_failed action that fires when enforce_username_whitelist
	 * returns a WP_Error. We use this only as a fallback — the main log is already
	 * written inside enforce_username_whitelist(), so here we just no-op.
	 */
	public function on_unauthorized_username( $username ) {
		// Main logging already done in enforce_username_whitelist(); nothing extra needed.
	}
}
