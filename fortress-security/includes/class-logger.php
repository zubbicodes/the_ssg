<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Fortress_Logger {

	private static $instance;

	public static function instance() : self {
		if ( ! self::$instance ) self::$instance = new self();
		return self::$instance;
	}

	private function __construct() {}

	/* ── Hook in ──────────────────────────────────────────────────────── */
	public function init() {
		if ( ! get_option( 'fortress_enabled' ) ) return;
		if ( ! get_option( 'fortress_logging_enabled' ) ) return;

		// Log requests — shutdown fires on all pages including wp-login.php
		add_action( 'shutdown', [ $this, 'log_request' ] );

		// Track login failures separately for brute-force detection
		add_action( 'wp_login_failed', [ $this, 'on_login_fail' ] );
		add_action( 'wp_login',        [ $this, 'on_login_success' ], 10, 2 );
	}

	/* ── Log the current request ──────────────────────────────────────── */
	public function log_request() {
		// Avoid double-logging: only run once
		static $logged = false;
		if ( $logged ) return;
		$logged = true;

		// Skip admin-ajax polling and cron
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		if (
			strpos( $uri, 'admin-ajax.php' ) !== false ||
			strpos( $uri, 'wp-cron.php' )   !== false ||
			( defined( 'DOING_CRON' )  && DOING_CRON ) ||
			( defined( 'DOING_AJAX' )  && DOING_AJAX && ! is_admin() )
		) {
			return;
		}

		$ip     = self::get_ip();
		$ua     = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 512 ) : '';
		$ref    = isset( $_SERVER['HTTP_REFERER'] )    ? substr( $_SERVER['HTTP_REFERER'],    0, 512 ) : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] )  ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET';

		$assessment = Fortress_Detector::analyse();

		$log_id = Fortress_DB::insert_log( [
			'ip_address'     => $ip,
			'request_method' => $method,
			'request_uri'    => substr( $uri, 0, 2048 ),
			'user_agent'     => $ua,
			'referer'        => $ref,
			'http_status'    => http_response_code() ?: 200,
			'is_suspicious'  => $assessment['is_suspicious'] ? 1 : 0,
			'threat_type'    => $assessment['threat_type'],
			'threat_score'   => $assessment['threat_score'],
			'user_id'        => get_current_user_id(),
			'blocked'        => 0,
		] );

		// Discord notification for high-score suspicious requests
		if ( $assessment['is_suspicious'] && $assessment['score'] >= 40 ) {
			$types = $assessment['threat_type'] ?? '';
			if ( strpos( $types, 'scanner' ) !== false ) {
				Fortress_Discord::alert_scanner( $ip, $ua, $uri );
			} else {
				Fortress_Discord::alert_suspicious( $ip, $uri, $types, $assessment['score'] );
			}
		}
	}

	/* ── Login failure ────────────────────────────────────────────────── */
	public function on_login_fail( $username ) {
		$ip  = self::get_ip();
		$uri = '/wp-login.php';
		$ua  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 512 ) : '';

		// Skip if firewall's username-whitelist enforcement already logged this attempt
		// (it sets a transient keyed by IP to signal it already created a log row)
		$transient_key = 'fortress_bad_username_' . md5( $ip );
		if ( get_transient( $transient_key ) ) {
			delete_transient( $transient_key );
			// Still run brute-force checks below
		} else {
			Fortress_DB::insert_log( [
				'ip_address'         => $ip,
				'request_method'     => 'POST',
				'request_uri'        => $uri,
				'user_agent'         => $ua,
				'is_suspicious'      => 1,
				'threat_type'        => 'login_fail',
				'threat_score'       => 30,
				'attempted_username' => sanitize_user( $username ),
			] );
		}

		$threshold = (int) get_option( 'fortress_brute_threshold', 5 );
		$window    = (int) get_option( 'fortress_brute_window',    10 );
		$fails     = Fortress_DB::count_recent_login_fails( $ip, $window );

		// Single fail notification
		if ( $fails === 1 ) {
			Fortress_Discord::alert_login_fail( $ip, $username, $fails );
		}

		// Brute force threshold
		if ( $fails === $threshold ) {
			Fortress_Discord::alert_brute_force( $ip, $fails );
		}
	}

	/* ── Login success ────────────────────────────────────────────────── */
	public function on_login_success( $user_login, $user ) {
		$ip = self::get_ip();
		Fortress_DB::insert_log( [
			'ip_address'     => $ip,
			'request_method' => 'POST',
			'request_uri'    => '/wp-login.php',
			'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 512 ) : '',
			'is_suspicious'  => 0,
			'threat_type'    => 'login_success',
			'threat_score'   => 0,
			'user_id'        => $user->ID,
		] );
	}

	/* ── Helpers ──────────────────────────────────────────────────────── */
	public static function get_ip() : string {
		$keys = [
			'HTTP_CF_CONNECTING_IP',   // Cloudflare
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		];
		foreach ( $keys as $k ) {
			if ( ! empty( $_SERVER[ $k ] ) ) {
				$ip = trim( explode( ',', $_SERVER[ $k ] )[0] );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}
		return '0.0.0.0';
	}
}
