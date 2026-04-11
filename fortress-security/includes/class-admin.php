<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Fortress_Admin {

	private static $instance;

	public static function instance() : self {
		if ( ! self::$instance ) self::$instance = new self();
		return self::$instance;
	}

	private function __construct() {}

	public function init() {
		add_action( 'admin_menu',            [ $this, 'register_menus' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
		add_action( 'admin_post_fortress_save_settings', [ $this, 'handle_save_settings' ] );
		add_action( 'admin_post_fortress_add_ip',        [ $this, 'handle_add_ip' ] );
		add_action( 'admin_post_fortress_remove_ip',     [ $this, 'handle_remove_ip' ] );
		add_action( 'admin_post_fortress_toggle_ip',     [ $this, 'handle_toggle_ip' ] );
		add_action( 'wp_ajax_fortress_test_discord',     [ $this, 'ajax_test_discord' ] );
		add_action( 'admin_post_fortress_clear_logs',    [ $this, 'handle_clear_logs' ] );
		add_action( 'wp_ajax_fortress_stats',            [ $this, 'ajax_stats' ] );
		add_action( 'wp_ajax_fortress_run_scan',         [ $this, 'ajax_run_scan' ] );
		add_action( 'wp_ajax_fortress_dismiss_finding',  [ $this, 'ajax_dismiss_finding' ] );
	}

	/* ── Menu ─────────────────────────────────────────────────────────── */
	public function register_menus() {
		add_menu_page(
			'The SSG',
			'The SSG',
			'manage_options',
			'fortress-security',
			[ $this, 'page_dashboard' ],
			'dashicons-shield',
			3
		);
		add_submenu_page( 'fortress-security', 'Dashboard',     'Dashboard',     'manage_options', 'fortress-security',    [ $this, 'page_dashboard' ] );
		add_submenu_page( 'fortress-security', 'Traffic Logs',  'Traffic Logs',  'manage_options', 'fortress-logs',        [ $this, 'page_logs' ] );
		add_submenu_page( 'fortress-security', 'Security Scan', 'Security Scan', 'manage_options', 'fortress-scanner',     [ $this, 'page_scanner' ] );
		add_submenu_page( 'fortress-security', 'IP Manager',    'IP Manager',    'manage_options', 'fortress-ip-manager',  [ $this, 'page_ip_manager' ] );
		add_submenu_page( 'fortress-security', 'Settings',      'Settings',      'manage_options', 'fortress-settings',    [ $this, 'page_settings' ] );
	}

	/* ── Assets ───────────────────────────────────────────────────────── */
	public function enqueue_assets( $hook ) {
		if ( strpos( $hook, 'fortress' ) === false ) return;
		wp_enqueue_style(
			'fortress-admin',
			FORTRESS_PLUGIN_URL . 'admin/css/fortress-admin.css',
			[],
			FORTRESS_VERSION
		);
		wp_enqueue_script(
			'fortress-admin',
			FORTRESS_PLUGIN_URL . 'admin/js/fortress-admin.js',
			[ 'jquery' ],
			FORTRESS_VERSION,
			true
		);
		wp_localize_script( 'fortress-admin', 'FortressAdmin', [
			'ajaxurl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'fortress_ajax' ),
		] );
	}

	/* ── Page renderers ───────────────────────────────────────────────── */
	public function page_dashboard() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		include FORTRESS_PLUGIN_DIR . 'admin/views/dashboard.php';
	}

	public function page_logs() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		include FORTRESS_PLUGIN_DIR . 'admin/views/logs.php';
	}

	public function page_ip_manager() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		include FORTRESS_PLUGIN_DIR . 'admin/views/ip-manager.php';
	}

	public function page_scanner() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		include FORTRESS_PLUGIN_DIR . 'admin/views/scanner.php';
	}

	public function page_settings() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		include FORTRESS_PLUGIN_DIR . 'admin/views/settings.php';
	}

	/* ── Handle: save settings ────────────────────────────────────────── */
	public function handle_save_settings() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		check_admin_referer( 'fortress_save_settings' );

		$checkboxes = [
			'fortress_enabled', 'fortress_reg_lock', 'fortress_ip_whitelist_enabled',
			'fortress_block_xmlrpc', 'fortress_logging_enabled',
			'fortress_discord_enabled', 'fortress_discord_on_block',
			'fortress_discord_on_login_fail', 'fortress_discord_on_scan', 'fortress_discord_on_brute',
		];
		foreach ( $checkboxes as $key ) {
			update_option( $key, isset( $_POST[ $key ] ) ? 1 : 0 );
		}

		$texts = [
			'fortress_discord_webhook'    => 'esc_url_raw',
			'fortress_whitelist_redirect' => 'esc_url_raw',
		];
		foreach ( $texts as $key => $san ) {
			if ( isset( $_POST[ $key ] ) ) {
				update_option( $key, $san( wp_unslash( $_POST[ $key ] ) ) );
			}
		}

		$ints = [
			'fortress_log_retention_days' => [ 1, 365 ],
			'fortress_brute_threshold'    => [ 1, 100 ],
			'fortress_brute_window'       => [ 1, 1440 ],
		];
		foreach ( $ints as $key => [ $min, $max ] ) {
			if ( isset( $_POST[ $key ] ) ) {
				update_option( $key, max( $min, min( $max, (int) $_POST[ $key ] ) ) );
			}
		}

		wp_safe_redirect( add_query_arg( [ 'page' => 'fortress-settings', 'saved' => 1 ], admin_url( 'admin.php' ) ) );
		exit;
	}

	/* ── Handle: add IP ───────────────────────────────────────────────── */
	public function handle_add_ip() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		check_admin_referer( 'fortress_add_ip' );

		$ip    = sanitize_text_field( wp_unslash( $_POST['ip_address'] ?? '' ) );
		$label = sanitize_text_field( wp_unslash( $_POST['label']      ?? '' ) );

		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			Fortress_DB::add_to_whitelist( $ip, $label, get_current_user_id() );
		}

		wp_safe_redirect( add_query_arg( [ 'page' => 'fortress-ip-manager', 'added' => 1 ], admin_url( 'admin.php' ) ) );
		exit;
	}

	/* ── Handle: remove IP ────────────────────────────────────────────── */
	public function handle_remove_ip() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		check_admin_referer( 'fortress_remove_ip' );

		Fortress_DB::remove_from_whitelist( (int) ( $_POST['entry_id'] ?? 0 ) );

		wp_safe_redirect( add_query_arg( [ 'page' => 'fortress-ip-manager', 'removed' => 1 ], admin_url( 'admin.php' ) ) );
		exit;
	}

	/* ── Handle: toggle IP ────────────────────────────────────────────── */
	public function handle_toggle_ip() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		check_admin_referer( 'fortress_toggle_ip' );

		Fortress_DB::toggle_whitelist_entry(
			(int) ( $_POST['entry_id'] ?? 0 ),
			(int) ( $_POST['active']   ?? 0 )
		);

		wp_safe_redirect( add_query_arg( [ 'page' => 'fortress-ip-manager' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	/* ── AJAX: test Discord ───────────────────────────────────────────── */
	public function ajax_test_discord() {
		check_ajax_referer( 'fortress_ajax', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );

		$webhook = get_option( 'fortress_discord_webhook', '' );
		if ( empty( $webhook ) ) {
			wp_send_json_error( 'No webhook URL saved. Save your settings first.' );
		}

		Fortress_Discord::test();
		wp_send_json_success( 'Test message sent. Check your Discord channel.' );
	}

	/* ── Handle: clear logs ───────────────────────────────────────────── */
	public function handle_clear_logs() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );
		check_admin_referer( 'fortress_clear_logs' );

		global $wpdb;
		$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}fortress_logs" );

		wp_safe_redirect( add_query_arg( [ 'page' => 'fortress-logs', 'cleared' => 1 ], admin_url( 'admin.php' ) ) );
		exit;
	}

	/* ── AJAX: live stats ─────────────────────────────────────────────── */
	public function ajax_stats() {
		check_ajax_referer( 'fortress_ajax', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );

		wp_send_json_success( Fortress_DB::get_stats() );
	}

	/* ── AJAX: run security scan ──────────────────────────────────────── */
	public function ajax_run_scan() {
		check_ajax_referer( 'fortress_ajax', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );

		$scope   = isset( $_POST['scope'] ) && $_POST['scope'] === 'quick' ? 'quick' : 'full';
		$results = Fortress_Scanner::run_scan( $scope );

		// Notify Discord if critical findings
		if ( $results['critical_count'] > 0 ) {
			Fortress_Discord::send(
				'Security Scan — Critical Issues Found',
				"A security scan found **{$results['critical_count']} critical issue(s)** on your site.",
				0xE74C3C,
				[
					[ 'name' => 'Critical',  'value' => (string) $results['critical_count'] ],
					[ 'name' => 'Warnings',  'value' => (string) $results['warning_count'] ],
					[ 'name' => 'Files Scanned', 'value' => (string) $results['files_scanned'] ],
					[ 'name' => 'Site',      'value' => get_bloginfo( 'url' ) ],
				],
				'danger'
			);
		}

		wp_send_json_success( $results );
	}

	/* ── AJAX: dismiss / restore finding ─────────────────────────────── */
	public function ajax_dismiss_finding() {
		check_ajax_referer( 'fortress_ajax', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden' );

		$id      = sanitize_text_field( $_POST['finding_id'] ?? '' );
		$action  = sanitize_text_field( $_POST['dismiss_action'] ?? 'dismiss' );

		if ( ! $id ) wp_send_json_error( 'No ID' );

		$dismissed = get_option( 'fortress_dismissed_findings', [] );

		if ( $action === 'dismiss' ) {
			$dismissed[] = $id;
		} else {
			$dismissed = array_values( array_diff( $dismissed, [ $id ] ) );
		}

		update_option( 'fortress_dismissed_findings', array_unique( $dismissed ), false );
		wp_send_json_success();
	}
}
