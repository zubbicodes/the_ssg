<?php
if (!defined('ABSPATH'))
	exit;

class Fortress_DB
{

	const LOG_TABLE = 'fortress_logs';
	const WHITELIST_TABLE = 'fortress_ip_whitelist';
	const BLACKLIST_TABLE = 'fortress_ip_blacklist';
	const USR_WHITELIST_TABLE = 'fortress_username_whitelist';

	/* ── Install (activation) ─────────────────────────────────────────── */
	public static function install()
	{
		global $wpdb;
		$charset = $wpdb->get_charset_collate();
		$log_t = $wpdb->prefix . self::LOG_TABLE;
		$wl_t = $wpdb->prefix . self::WHITELIST_TABLE;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		// dbDelta requires: 2 spaces before PRIMARY KEY, each column on its own line,
		// no leading whitespace on lines, and one call per table.
		dbDelta("CREATE TABLE $log_t (
id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
log_time datetime NOT NULL,
ip_address varchar(45) NOT NULL DEFAULT '',
request_method varchar(10) NOT NULL DEFAULT 'GET',
request_uri text NOT NULL,
user_agent text,
referer text,
http_status smallint(6) NOT NULL DEFAULT 200,
is_suspicious tinyint(1) NOT NULL DEFAULT 0,
threat_type varchar(120) DEFAULT NULL,
threat_score tinyint(3) unsigned NOT NULL DEFAULT 0,
user_id bigint(20) unsigned NOT NULL DEFAULT 0,
blocked tinyint(1) NOT NULL DEFAULT 0,
PRIMARY KEY  (id),
KEY idx_ip (ip_address),
KEY idx_time (log_time),
KEY idx_sus (is_suspicious),
KEY idx_blocked (blocked)
) $charset;");

		dbDelta("CREATE TABLE $wl_t (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
ip_address varchar(45) NOT NULL,
label varchar(120) NOT NULL DEFAULT '',
added_by bigint(20) unsigned NOT NULL DEFAULT 0,
added_at datetime NOT NULL,
is_active tinyint(1) NOT NULL DEFAULT 1,
PRIMARY KEY  (id),
UNIQUE KEY uq_ip (ip_address)
) $charset;");

		$bl_t = $wpdb->prefix . self::BLACKLIST_TABLE;
		$uwl_t = $wpdb->prefix . self::USR_WHITELIST_TABLE;

		dbDelta("CREATE TABLE $bl_t (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
ip_address varchar(45) NOT NULL,
label varchar(120) NOT NULL DEFAULT '',
added_by bigint(20) unsigned NOT NULL DEFAULT 0,
added_at datetime NOT NULL,
expires_at datetime DEFAULT NULL,
PRIMARY KEY  (id),
UNIQUE KEY uq_ip (ip_address)
) $charset;");

		dbDelta("CREATE TABLE $uwl_t (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
username varchar(60) NOT NULL,
label varchar(120) NOT NULL DEFAULT '',
added_by bigint(20) unsigned NOT NULL DEFAULT 0,
added_at datetime NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY uq_username (username)
) $charset;");

		// Add attempted_username column if missing (safe on re-run)
		$wpdb->query("ALTER TABLE {$wpdb->prefix}" . self::LOG_TABLE . " ADD COLUMN IF NOT EXISTS attempted_username varchar(60) DEFAULT NULL");

		// Default settings
		$defaults = [
			'fortress_enabled' => 1,
			'fortress_reg_lock' => 1,
			'fortress_ip_whitelist_enabled' => 0,
			'fortress_block_xmlrpc' => 1,
			'fortress_logging_enabled' => 1,
			'fortress_log_retention_days' => 30,
			'fortress_discord_webhook' => '',
			'fortress_discord_enabled' => 0,
			'fortress_discord_on_block' => 1,
			'fortress_discord_on_login_fail' => 1,
			'fortress_discord_on_scan' => 1,
			'fortress_discord_on_brute' => 1,
			'fortress_brute_threshold' => 5,
			'fortress_brute_window' => 10,
			'fortress_emergency_token' => wp_generate_password(32, false),
			'fortress_whitelist_redirect' => '',
			'fortress_firewall_enabled' => 1,
			'fortress_username_whitelist_enabled' => 0,
		];
		foreach ($defaults as $key => $val) {
			add_option($key, $val);
		}

		// Schedule cleanup cron
		if (!wp_next_scheduled('fortress_cleanup')) {
			wp_schedule_event(time(), 'daily', 'fortress_cleanup');
		}
	}

	/* ── Deactivation ─────────────────────────────────────────────────── */
	public static function deactivate()
	{
		wp_clear_scheduled_hook('fortress_cleanup');
	}

	/* ── Ensure tables exist (runs on admin_init, catches missed activation) */
	public static function maybe_create_tables()
	{
		global $wpdb;
		$log_t = $wpdb->prefix . self::LOG_TABLE;
		// Quick check — only run dbDelta if table is missing
		if ($wpdb->get_var("SHOW TABLES LIKE '$log_t'") !== $log_t) {
			self::install();
		} else {
			// Ensure new columns exist on existing installs
			$wpdb->query("ALTER TABLE {$log_t} ADD COLUMN IF NOT EXISTS attempted_username varchar(60) DEFAULT NULL");
			// Ensure new tables exist
			$bl_t = $wpdb->prefix . self::BLACKLIST_TABLE;
			$uwl_t = $wpdb->prefix . self::USR_WHITELIST_TABLE;
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			$charset = $wpdb->get_charset_collate();
			dbDelta("CREATE TABLE $bl_t (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
ip_address varchar(45) NOT NULL,
label varchar(120) NOT NULL DEFAULT '',
added_by bigint(20) unsigned NOT NULL DEFAULT 0,
added_at datetime NOT NULL,
expires_at datetime DEFAULT NULL,
PRIMARY KEY  (id),
UNIQUE KEY uq_ip (ip_address)
) $charset;");
			dbDelta("CREATE TABLE $uwl_t (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
username varchar(60) NOT NULL,
label varchar(120) NOT NULL DEFAULT '',
added_by bigint(20) unsigned NOT NULL DEFAULT 0,
added_at datetime NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY uq_username (username)
) $charset;");
		}
	}

	/* ── Insert log row ───────────────────────────────────────────────── */
	public static function insert_log(array $data)
	{
		global $wpdb;
		$defaults = [
			'log_time' => current_time('mysql'),
			'ip_address' => '',
			'request_method' => 'GET',
			'request_uri' => '',
			'user_agent' => '',
			'referer' => '',
			'http_status' => 200,
			'is_suspicious' => 0,
			'threat_type' => null,
			'threat_score' => 0,
			'user_id' => 0,
			'blocked' => 0,
			'attempted_username' => null,
		];
		$row = array_merge($defaults, $data);
		$formats = ['%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%d', '%d', '%d', '%s'];
		$wpdb->insert($wpdb->prefix . self::LOG_TABLE, $row, $formats);
		return $wpdb->insert_id;
	}

	/* ── Delete a single log row ───────────────────────────────────────── */
	public static function delete_log(int $id)
	{
		global $wpdb;
		$wpdb->delete($wpdb->prefix . self::LOG_TABLE, ['id' => $id], ['%d']);
	}

	/* ── Query logs ───────────────────────────────────────────────────── */
	public static function get_logs(array $args = [])
	{
		global $wpdb;
		$t = $wpdb->prefix . self::LOG_TABLE;

		$defaults = [
			'per_page' => 50,
			'page' => 1,
			'ip' => '',
			'suspicious' => '',
			'blocked' => '',
			'date_from' => '',
			'date_to' => '',
			'search' => '',
		];
		$args = wp_parse_args($args, $defaults);
		$where = ['1=1'];
		$params = [];

		if ($args['ip']) {
			$where[] = 'ip_address = %s';
			$params[] = sanitize_text_field($args['ip']);
		}
		if ($args['suspicious'] !== '') {
			$where[] = 'is_suspicious = %d';
			$params[] = (int) $args['suspicious'];
		}
		if ($args['blocked'] !== '') {
			$where[] = 'blocked = %d';
			$params[] = (int) $args['blocked'];
		}
		if ($args['date_from']) {
			$where[] = 'log_time >= %s';
			$params[] = sanitize_text_field($args['date_from']) . ' 00:00:00';
		}
		if ($args['date_to']) {
			$where[] = 'log_time <= %s';
			$params[] = sanitize_text_field($args['date_to']) . ' 23:59:59';
		}
		if ($args['search']) {
			$where[] = '(request_uri LIKE %s OR ip_address LIKE %s OR user_agent LIKE %s)';
			$like = '%' . $wpdb->esc_like(sanitize_text_field($args['search'])) . '%';
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
		}

		$where_sql = implode(' AND ', $where);
		$offset = ((int) $args['page'] - 1) * (int) $args['per_page'];
		$limit = (int) $args['per_page'];

		$count_sql = "SELECT COUNT(*) FROM {$t} WHERE {$where_sql}";
		$rows_sql = "SELECT * FROM {$t} WHERE {$where_sql} ORDER BY log_time DESC LIMIT {$limit} OFFSET {$offset}";

		if ($params) {
			$count_sql = $wpdb->prepare($count_sql, $params);
			$rows_sql = $wpdb->prepare($rows_sql, $params);
		}

		return [
			'total' => (int) $wpdb->get_var($count_sql),
			'rows' => $wpdb->get_results($rows_sql),
		];
	}

	/* ── Stats ────────────────────────────────────────────────────────── */
	public static function get_stats()
	{
		global $wpdb;
		$t = $wpdb->prefix . self::LOG_TABLE;
		$day = current_time('mysql');
		$day = substr($day, 0, 10);

		return [
			'total_today' => (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$t} WHERE DATE(log_time)=%s", $day)),
			'suspicious_today' => (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$t} WHERE DATE(log_time)=%s AND is_suspicious=1", $day)),
			'blocked_today' => (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$t} WHERE DATE(log_time)=%s AND blocked=1", $day)),
			'total_all' => (int) $wpdb->get_var("SELECT COUNT(*) FROM {$t}"),
			'top_ips' => $wpdb->get_results("SELECT ip_address, COUNT(*) as hits FROM {$t} WHERE DATE(log_time)='{$day}' GROUP BY ip_address ORDER BY hits DESC LIMIT 5"),
			'threat_breakdown' => $wpdb->get_results("SELECT threat_type, COUNT(*) as cnt FROM {$t} WHERE is_suspicious=1 AND threat_type IS NOT NULL GROUP BY threat_type ORDER BY cnt DESC LIMIT 8"),
			'recent_threats' => $wpdb->get_results("SELECT * FROM {$t} WHERE is_suspicious=1 ORDER BY log_time DESC LIMIT 10"),
		];
	}

	/* ── IP Whitelist helpers ─────────────────────────────────────────── */
	public static function get_whitelist()
	{
		global $wpdb;
		return $wpdb->get_results("SELECT * FROM {$wpdb->prefix}" . self::WHITELIST_TABLE . " ORDER BY added_at DESC");
	}

	/* ── IP Blacklist helpers ─────────────────────────────────────────── */
	public static function get_blacklist()
	{
		global $wpdb;
		return $wpdb->get_results("SELECT * FROM {$wpdb->prefix}" . self::BLACKLIST_TABLE . " ORDER BY added_at DESC");
	}

	public static function add_to_blacklist(string $ip, string $label = '', int $user_id = 0, ?string $expires_at = null)
	{
		global $wpdb;
		$row = [
			'ip_address' => sanitize_text_field($ip),
			'label' => sanitize_text_field($label),
			'added_by' => $user_id,
			'added_at' => current_time('mysql'),
			'expires_at' => $expires_at,
		];
		$wpdb->replace($wpdb->prefix . self::BLACKLIST_TABLE, $row, ['%s', '%s', '%d', '%s', '%s']);
	}

	public static function remove_from_blacklist(int $id)
	{
		global $wpdb;
		$wpdb->delete($wpdb->prefix . self::BLACKLIST_TABLE, ['id' => $id], ['%d']);
	}

	public static function is_ip_blacklisted(string $ip): bool
	{
		global $wpdb;
		$t = $wpdb->prefix . self::BLACKLIST_TABLE;
		$now = current_time('mysql');
		return (bool) $wpdb->get_var($wpdb->prepare(
			"SELECT id FROM {$t} WHERE ip_address=%s AND (expires_at IS NULL OR expires_at > %s) LIMIT 1",
			$ip,
			$now
		));
	}

	/* ── Username Whitelist helpers ───────────────────────────────────── */
	public static function get_username_whitelist()
	{
		global $wpdb;
		return $wpdb->get_results("SELECT * FROM {$wpdb->prefix}" . self::USR_WHITELIST_TABLE . " ORDER BY added_at DESC");
	}

	public static function add_to_username_whitelist(string $username, string $label = '', int $user_id = 0)
	{
		global $wpdb;
		$wpdb->replace(
			$wpdb->prefix . self::USR_WHITELIST_TABLE,
			[
				'username' => sanitize_user($username),
				'label' => sanitize_text_field($label),
				'added_by' => $user_id,
				'added_at' => current_time('mysql'),
			],
			['%s', '%s', '%d', '%s']
		);
	}

	public static function remove_from_username_whitelist(int $id)
	{
		global $wpdb;
		$wpdb->delete($wpdb->prefix . self::USR_WHITELIST_TABLE, ['id' => $id], ['%d']);
	}

	public static function is_username_whitelisted(string $username): bool
	{
		global $wpdb;
		$t = $wpdb->prefix . self::USR_WHITELIST_TABLE;
		return (bool) $wpdb->get_var($wpdb->prepare(
			"SELECT id FROM {$t} WHERE username=%s LIMIT 1",
			sanitize_user($username)
		));
	}

	public static function username_whitelist_count(): int
	{
		global $wpdb;
		return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}" . self::USR_WHITELIST_TABLE);
	}

	public static function add_to_whitelist(string $ip, string $label = '', int $user_id = 0)
	{
		global $wpdb;
		$wpdb->replace(
			$wpdb->prefix . self::WHITELIST_TABLE,
			[
				'ip_address' => sanitize_text_field($ip),
				'label' => sanitize_text_field($label),
				'added_by' => $user_id,
				'added_at' => current_time('mysql'),
				'is_active' => 1,
			],
			['%s', '%s', '%d', '%s', '%d']
		);
	}

	public static function remove_from_whitelist(int $id)
	{
		global $wpdb;
		$wpdb->delete($wpdb->prefix . self::WHITELIST_TABLE, ['id' => $id], ['%d']);
	}

	public static function toggle_whitelist_entry(int $id, int $active)
	{
		global $wpdb;
		$wpdb->update(
			$wpdb->prefix . self::WHITELIST_TABLE,
			['is_active' => $active],
			['id' => $id],
			['%d'],
			['%d']
		);
	}

	public static function is_ip_whitelisted(string $ip): bool
	{
		global $wpdb;
		$t = $wpdb->prefix . self::WHITELIST_TABLE;
		return (bool) $wpdb->get_var($wpdb->prepare(
			"SELECT id FROM {$t} WHERE ip_address=%s AND is_active=1 LIMIT 1",
			$ip
		));
	}

	/* ── Login attempts (stored in log table) ─────────────────────────── */
	public static function count_recent_login_fails(string $ip, int $minutes): int
	{
		global $wpdb;
		$t = $wpdb->prefix . self::LOG_TABLE;
		$from = date('Y-m-d H:i:s', current_time('timestamp') - $minutes * 60);
		return (int) $wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(*) FROM {$t} WHERE ip_address=%s AND threat_type='login_fail' AND log_time >= %s",
			$ip,
			$from
		));
	}

	/* ── Cleanup old logs ─────────────────────────────────────────────── */
	public static function cleanup()
	{
		global $wpdb;
		$days = (int) get_option('fortress_log_retention_days', 30);
		$t = $wpdb->prefix . self::LOG_TABLE;
		$cutoff = date('Y-m-d H:i:s', current_time('timestamp') - $days * DAY_IN_SECONDS);
		$wpdb->query($wpdb->prepare("DELETE FROM {$t} WHERE log_time < %s", $cutoff));
	}
}

add_action('fortress_cleanup', ['Fortress_DB', 'cleanup']);
