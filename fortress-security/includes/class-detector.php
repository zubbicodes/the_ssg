<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Analyses the current HTTP request and returns a threat assessment.
 */
class Fortress_Detector {

	/* ── Patterns ─────────────────────────────────────────────────────── */

	private static $sql_patterns = [
		'/(\%27)|(\')|(\-\-)|(\%23)|(#)/i',
		'/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i',
		'/\b(union|select|insert|update|delete|drop|create|alter|exec|execute|xp_)\b/i',
		'/\bOR\b\s+[\'\d]/i',
		'/benchmark\s*\(/i',
		'/sleep\s*\(\s*\d/i',
		'/LOAD_FILE\s*\(/i',
		'/INTO\s+OUTFILE/i',
		'/GROUP\s+BY.+HAVING/i',
		'/CAST\s*\(/i',
		'/CONVERT\s*\(/i',
	];

	private static $xss_patterns = [
		'/<script[\s\S]*?>/i',
		'/javascript\s*:/i',
		'/on(load|error|click|mouse|focus|blur|key|submit|change|scroll|resize)\s*=/i',
		'/expression\s*\(/i',
		'/vbscript\s*:/i',
		'/<\s*iframe/i',
		'/<\s*img[^>]+onerror/i',
		'/document\.(cookie|location|write)/i',
		'/eval\s*\(/i',
		'/base64_decode\s*\(/i',
	];

	private static $traversal_patterns = [
		'/\.\.\//',
		'/\.\.\\\\/',
		'/%2e%2e%2f/i',
		'/%2e%2e\//i',
		'/\.\.%2f/i',
		'/%252e%252e%252f/i',
	];

	private static $rce_patterns = [
		'/\b(phpinfo|system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i',
		'/\b(wget|curl|fetch)\s+http/i',
		'/\|\s*(bash|sh|cmd|powershell)/i',
		'/`[^`]+`/',
		'/\$\(.*\)/',
		'/;\s*(ls|cat|pwd|id|uname|whoami)\b/i',
	];

	private static $scanner_agents = [
		'sqlmap', 'nikto', 'havij', 'masscan', 'nmap', 'nessus',
		'openvas', 'w3af', 'skipfish', 'wfuzz', 'dirbuster', 'dirb',
		'gobuster', 'hydra', 'medusa', 'burpsuite', 'zgrab',
		'python-requests', 'go-http-client', 'libwww-perl', 'curl/',
		'wget/', 'scrapy', 'semrushbot', 'ahrefsbot', 'mj12bot',
		'dotdotpwn', 'paros', 'webinspect', 'acunetix', 'appscan',
		'netsparker', 'httprint', 'whatweb', 'wapiti', 'xsser',
	];

	private static $sensitive_paths = [
		'wp-config', '.env', '.git', 'phpinfo', 'server-status',
		'server-info', '.htpasswd', '.htaccess', 'web.config',
		'backup', 'dump', 'sql', '.bak', '.old', '.swp',
		'adminer', 'phpmyadmin', 'myadmin', 'pma',
		'shell', 'webshell', 'cmd', 'console',
		'eval-stdin', 'php-reverse', 'c99', 'r57',
	];

	/* ── Main analyse method ──────────────────────────────────────────── */
	public static function analyse() : array {
		$uri     = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$ua      = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
		$method  = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET';

		// Combine all user input for pattern checks
		$input_haystack = $uri;
		if ( $method === 'POST' ) {
			foreach ( $_POST as $v ) {
				if ( is_string( $v ) ) $input_haystack .= ' ' . $v;
			}
		}
		foreach ( $_GET as $v ) {
			if ( is_string( $v ) ) $input_haystack .= ' ' . $v;
		}

		$score  = 0;
		$types  = [];

		// SQL injection
		foreach ( self::$sql_patterns as $p ) {
			if ( preg_match( $p, $input_haystack ) ) {
				$types[] = 'sql_injection';
				$score  += 40;
				break;
			}
		}

		// XSS
		foreach ( self::$xss_patterns as $p ) {
			if ( preg_match( $p, $input_haystack ) ) {
				$types[] = 'xss';
				$score  += 35;
				break;
			}
		}

		// Path traversal
		foreach ( self::$traversal_patterns as $p ) {
			if ( preg_match( $p, $uri ) ) {
				$types[] = 'path_traversal';
				$score  += 35;
				break;
			}
		}

		// RCE
		foreach ( self::$rce_patterns as $p ) {
			if ( preg_match( $p, $input_haystack ) ) {
				$types[] = 'rce_attempt';
				$score  += 50;
				break;
			}
		}

		// Scanner user-agent
		$ua_lower = strtolower( $ua );
		foreach ( self::$scanner_agents as $bot ) {
			if ( strpos( $ua_lower, $bot ) !== false ) {
				$types[] = 'scanner';
				$score  += 30;
				break;
			}
		}

		// Empty user-agent
		if ( empty( $ua ) && in_array( $method, [ 'GET', 'POST' ], true ) ) {
			$types[] = 'no_user_agent';
			$score  += 10;
		}

		// Sensitive path probing
		$uri_lower = strtolower( $uri );
		foreach ( self::$sensitive_paths as $path ) {
			if ( strpos( $uri_lower, $path ) !== false ) {
				$types[] = 'sensitive_probe';
				$score  += 25;
				break;
			}
		}

		// xmlrpc.php access
		if ( strpos( $uri, 'xmlrpc.php' ) !== false ) {
			$types[] = 'xmlrpc_access';
			$score  += 15;
		}

		// Non-standard HTTP method
		if ( ! in_array( $method, [ 'GET', 'POST', 'HEAD', 'OPTIONS' ], true ) ) {
			$types[] = 'unusual_method';
			$score  += 20;
		}

		$score = min( $score, 100 );

		return [
			'score'         => $score,
			'is_suspicious' => $score >= 20,
			'types'         => $types,
			'threat_type'   => empty( $types ) ? null : implode( ',', array_unique( $types ) ),
		];
	}
}
