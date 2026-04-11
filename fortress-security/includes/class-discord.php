<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Fortress_Discord {

	/* ── Send a rich embed ────────────────────────────────────────────── */
	public static function send( string $title, string $description, int $color = 0xE74C3C, array $fields = [], string $level = 'danger' ) {
		if ( ! get_option( 'fortress_discord_enabled' ) ) return;
		$webhook = get_option( 'fortress_discord_webhook', '' );
		if ( empty( $webhook ) ) return;

		$icons = [
			'danger'  => ':rotating_light:',
			'warning' => ':warning:',
			'info'    => ':information_source:',
			'success' => ':white_check_mark:',
		];
		$icon = $icons[ $level ] ?? ':shield:';

		$embed = [
			'title'       => $icon . ' ' . $title,
			'description' => $description,
			'color'       => $color,
			'timestamp'   => date( 'c' ),
			'footer'      => [
				'text' => 'The SSG • ' . get_bloginfo( 'name' ),
			],
			'fields' => [],
		];

		foreach ( $fields as $f ) {
			$embed['fields'][] = [
				'name'   => $f['name']   ?? '',
				'value'  => $f['value']  ?? '',
				'inline' => $f['inline'] ?? true,
			];
		}

		$payload = [
			'username'   => 'The SSG',
			'avatar_url' => 'https://i.imgur.com/4M34hi2.png',
			'embeds'     => [ $embed ],
		];

		wp_remote_post( $webhook, [
			'headers'    => [ 'Content-Type' => 'application/json' ],
			'body'       => wp_json_encode( $payload ),
			'timeout'    => 5,
			'blocking'   => false,
			'sslverify'  => true,
		] );
	}

	/* ── Convenience alerts ───────────────────────────────────────────── */

	public static function alert_blocked( string $ip, string $uri, string $reason ) {
		if ( ! get_option( 'fortress_discord_on_block' ) ) return;
		self::send(
			'Access Blocked',
			"A request was **blocked** on your WordPress site.",
			0xE74C3C,
			[
				[ 'name' => 'IP Address', 'value' => "`{$ip}`" ],
				[ 'name' => 'URI',        'value' => "`" . substr( $uri, 0, 200 ) . "`" ],
				[ 'name' => 'Reason',     'value' => $reason ],
				[ 'name' => 'Site',       'value' => get_bloginfo( 'url' ) ],
			],
			'danger'
		);
	}

	public static function alert_login_fail( string $ip, string $username, int $fail_count ) {
		if ( ! get_option( 'fortress_discord_on_login_fail' ) ) return;
		self::send(
			'Failed Login Attempt',
			"Failed login attempt detected.",
			0xE67E22,
			[
				[ 'name' => 'IP Address', 'value' => "`{$ip}`" ],
				[ 'name' => 'Username',   'value' => esc_html( $username ) ],
				[ 'name' => 'Fail Count (window)', 'value' => (string) $fail_count ],
				[ 'name' => 'Site',       'value' => get_bloginfo( 'url' ) ],
			],
			'warning'
		);
	}

	public static function alert_brute_force( string $ip, int $attempts ) {
		if ( ! get_option( 'fortress_discord_on_brute' ) ) return;
		self::send(
			'Brute Force Detected',
			"**Brute force attack** in progress — IP has been flagged.",
			0x8E44AD,
			[
				[ 'name' => 'IP Address', 'value' => "`{$ip}`" ],
				[ 'name' => 'Attempts',   'value' => (string) $attempts ],
				[ 'name' => 'Site',       'value' => get_bloginfo( 'url' ) ],
			],
			'danger'
		);
	}

	public static function alert_scanner( string $ip, string $ua, string $uri ) {
		if ( ! get_option( 'fortress_discord_on_scan' ) ) return;
		self::send(
			'Scanner / Probe Detected',
			"A known scanner or vulnerability probe was detected.",
			0xC0392B,
			[
				[ 'name' => 'IP Address',  'value' => "`{$ip}`" ],
				[ 'name' => 'User Agent',  'value' => '`' . substr( $ua, 0, 120 ) . '`' ],
				[ 'name' => 'URI',         'value' => '`' . substr( $uri, 0, 200 ) . '`' ],
				[ 'name' => 'Site',        'value' => get_bloginfo( 'url' ) ],
			],
			'danger'
		);
	}

	public static function alert_suspicious( string $ip, string $uri, string $threat_type, int $score ) {
		self::send(
			'Suspicious Request',
			"A suspicious request was detected and logged.",
			0xD35400,
			[
				[ 'name' => 'IP Address',   'value' => "`{$ip}`" ],
				[ 'name' => 'URI',          'value' => '`' . substr( $uri, 0, 200 ) . '`' ],
				[ 'name' => 'Threat Type',  'value' => $threat_type ],
				[ 'name' => 'Threat Score', 'value' => (string) $score . '/100' ],
				[ 'name' => 'Site',         'value' => get_bloginfo( 'url' ) ],
			],
			'warning'
		);
	}

	/* ── Test webhook ─────────────────────────────────────────────────── */
	public static function test() {
		self::send(
			'Test Alert',
			'Your Fortress Security Discord integration is working correctly.',
			0x2ECC71,
			[
				[ 'name' => 'Site',   'value' => get_bloginfo( 'url' ) ],
				[ 'name' => 'Status', 'value' => ':white_check_mark: Connected' ],
			],
			'success'
		);
	}
}
