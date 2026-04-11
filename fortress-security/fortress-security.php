<?php
/**
 * Plugin Name: The SSG
 * Plugin URI:  #
 * Description: Advanced WordPress security — registration lockdown, admin IP whitelist, full traffic logging with threat detection, and Discord alerts.
 * Version:     1.0.0
 * Author:      Stratonally Dev Team
 * License:     GPL v2 or later
 * Text Domain: the-ssg
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'FORTRESS_VERSION',     '1.0.0' );
define( 'FORTRESS_PLUGIN_DIR',  plugin_dir_path( __FILE__ ) );
define( 'FORTRESS_PLUGIN_URL',  plugin_dir_url( __FILE__ ) );
define( 'FORTRESS_PLUGIN_FILE', __FILE__ );

/* ── Autoload classes ─────────────────────────────────────────────────── */
foreach ( [
	'class-db',
	'class-discord',
	'class-detector',
	'class-logger',
	'class-firewall',
	'class-scanner',
	'class-admin',
] as $file ) {
	require_once FORTRESS_PLUGIN_DIR . "includes/{$file}.php";
}

/* ── Activation / deactivation ────────────────────────────────────────── */
register_activation_hook( __FILE__,   [ 'Fortress_DB', 'install'    ] );
register_deactivation_hook( __FILE__, [ 'Fortress_DB', 'deactivate' ] );

/* ── Bootstrap ────────────────────────────────────────────────────────── */
add_action( 'plugins_loaded', function () {
	Fortress_Firewall::instance()->init();
	Fortress_Logger::instance()->init();
	if ( is_admin() ) {
		Fortress_Admin::instance()->init();
	}
}, 1 );

// Ensure DB tables exist even if activation hook was missed
add_action( 'admin_init', [ 'Fortress_DB', 'maybe_create_tables' ] );
