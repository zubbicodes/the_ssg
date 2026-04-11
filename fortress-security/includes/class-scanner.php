<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Fortress_Scanner {

	/* ── Malware patterns (PHP files) ─────────────────────────────────── */
	private static $file_patterns = [
		'eval_base64'       => [ '/eval\s*\(\s*base64_decode\s*\(/i',                    'critical', 'Eval + base64_decode — classic PHP backdoor obfuscation' ],
		'eval_gzip'         => [ '/eval\s*\(\s*gzinflate\s*\(/i',                        'critical', 'Eval + gzinflate — compressed payload execution' ],
		'eval_gzuncompress' => [ '/eval\s*\(\s*gzuncompress\s*\(/i',                     'critical', 'Eval + gzuncompress — compressed payload execution' ],
		'eval_rot13'        => [ '/eval\s*\(\s*str_rot13\s*\(/i',                        'critical', 'Eval + str_rot13 — obfuscated code execution' ],
		'eval_hex'          => [ '/eval\s*\(\s*hex2bin\s*\(/i',                          'critical', 'Eval + hex2bin — hex-encoded payload execution' ],
		'preg_replace_e'    => [ '/preg_replace\s*\(\s*[\'"].*\/e[\'"]/i',              'critical', 'preg_replace /e modifier — executes code in replacement string' ],
		'assert_input'      => [ '/assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',        'critical', 'assert() with user input — remote code execution vector' ],
		'create_function'   => [ '/create_function\s*\(\s*[\'"].*[\'"]\s*,\s*\$_/i',   'critical', 'create_function() with user input — code injection' ],
		'shell_user_input'  => [ '/shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',   'critical', 'shell_exec() with user input — OS command injection' ],
		'system_user_input' => [ '/\bsystem\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',     'critical', 'system() with user input — OS command injection' ],
		'passthru_input'    => [ '/passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',     'critical', 'passthru() with user input — OS command injection' ],
		'exec_input'        => [ '/\bexec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',       'critical', 'exec() with user input — OS command injection' ],
		'move_upload'       => [ '/move_uploaded_file\s*\(.*\$_(FILES|POST|GET)/i',     'critical', 'Unrestricted file upload — allows uploading backdoors' ],
		'file_put_input'    => [ '/file_put_contents\s*\(.*\$_(POST|GET|REQUEST)/i',    'critical', 'file_put_contents() with user input — writes arbitrary files' ],
		'base64_long'       => [ '/[\'"][A-Za-z0-9+\/]{500,}={0,2}[\'"]/i',            'warning',  'Long base64 string — may be encoded payload or backdoor' ],
		'hex_string'        => [ '/\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){9,}/i',   'warning',  'Long hex-encoded string — possible obfuscated code' ],
		'ob_callback'       => [ '/ob_start\s*\(\s*["\']?[a-zA-Z_]\w+["\']?\s*\)/i',   'warning',  'ob_start() with callback — output interception technique' ],
		'globals_hex'       => [ '/\$GLOBALS\s*\[\s*["\']0x[0-9a-f]+/i',               'warning',  'GLOBALS array with hex key — obfuscation indicator' ],
		'str_replace_array' => [ '/str_replace\s*\(\s*array\s*\(["\'].,/i',            'warning',  'str_replace with char-array — string deobfuscation pattern' ],
		'chr_concat'        => [ '/chr\s*\(\d+\)\s*\.\s*chr\s*\(\d+\)\s*\.\s*chr/i',  'warning',  'chr() concatenation — character-by-character string building (obfuscation)' ],
		'wpconfig_access'   => [ '/file_get_contents\s*\([\'"].*wp-config/i',           'critical', 'Reads wp-config.php — credential theft attempt' ],
		'remote_fopen'      => [ '/fopen\s*\(\s*["\']https?:\/\//i',                   'warning',  'fopen() with remote URL — possible remote file inclusion' ],
		'include_input'     => [ '/\b(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i', 'critical', 'Dynamic include with user input — remote/local file inclusion' ],
	];

	/* ── Database / content patterns ─────────────────────────────────── */
	private static $db_patterns = [
		'pharma_hack'       => [ '/\b(viagra|cialis|levitra|pharmacy|payday.{0,5}loan|xanax|tramadol|adderall)\b/i', 'critical', 'Pharma hack keywords — SEO spam injection' ],
		'casino_spam'       => [ '/\b(online.{0,10}casino|poker.{0,10}bonus|free.{0,10}slots|sports.{0,10}betting)\b/i', 'critical', 'Casino spam — SEO spam injection' ],
		'hidden_link'       => [ '/style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>.*<a\s+href/is', 'critical', 'Hidden link (display:none) — cloaked SEO spam' ],
		'iframe_inject'     => [ '/<iframe[^>]+src\s*=\s*["\']https?:\/\//i',           'critical', 'External iframe — common malware delivery vector' ],
		'js_unescape'       => [ '/document\.write\s*\(\s*unescape\s*\(/i',             'critical', 'document.write + unescape — encoded script injection' ],
		'js_atob'           => [ '/document\.write\s*\(\s*atob\s*\(/i',                 'critical', 'document.write + atob — base64 script injection' ],
		'eval_script'       => [ '/<script[^>]*>\s*eval\s*\(/i',                        'critical', 'eval() inside <script> tag — injected JavaScript eval' ],
		'ext_script'        => [ '/<script[^>]+src\s*=\s*["\']https?:\/\/(?!(?:cdn\.|ajax\.|maps\.))/i', 'warning', 'External script tag — verify this is intentional' ],
		'spam_tld'          => [ '/<a[^>]+href\s*=\s*["\'][^"\']*\.(ru|cn|tk|pw|top|xyz|win|bid|review)["\'][^>]*>/i', 'warning', 'Link to suspicious TLD — possible SEO spam' ],
		'base64_decode_db'  => [ '/base64_decode\s*\(["\'][A-Za-z0-9+\/]{100,}/i',     'critical', 'base64_decode with long string — encoded malicious content' ],
		'wordpress_inject'  => [ '/\$wpdb->query\s*\(\s*\$_(GET|POST|REQUEST)/i',      'critical', 'wpdb->query with user input — SQL injection in stored content' ],
	];

	/* ── Run full scan ────────────────────────────────────────────────── */
	public static function run_scan( string $scope = 'full' ) : array {
		@set_time_limit( 120 );

		$findings       = [];
		$files_scanned  = 0;
		$db_scanned     = 0;

		// File scans
		$dirs = [];

		// 1. Uploads — PHP files should NEVER exist here
		$dirs[] = [ WP_CONTENT_DIR . '/uploads', 'uploads_php', true ];

		// 2. Active theme
		$theme = get_template_directory();
		$dirs[] = [ $theme, 'theme', false ];

		// 3. Active child theme (if different)
		$child = get_stylesheet_directory();
		if ( $child !== $theme ) {
			$dirs[] = [ $child, 'child_theme', false ];
		}

		// 4. Active plugins
		if ( $scope === 'full' ) {
			$active = get_option( 'active_plugins', [] );
			foreach ( array_slice( $active, 0, 20 ) as $plugin_file ) {
				$plugin_dir = WP_PLUGIN_DIR . '/' . dirname( $plugin_file );
				if ( is_dir( $plugin_dir ) && $plugin_dir !== WP_PLUGIN_DIR . '/.' ) {
					$dirs[] = [ $plugin_dir, 'plugin:' . basename( $plugin_dir ), false ];
				}
			}
		}

		// 5. Recently modified files (last 14 days) in wp-content root
		$recent = self::find_recently_modified( WP_CONTENT_DIR, 14, [ 'php', 'js', 'html' ], 3 );
		foreach ( $recent as $f ) {
			$findings[] = [
				'id'          => md5( 'recent_' . $f['path'] ),
				'type'        => 'file',
				'severity'    => 'info',
				'category'    => 'recently_modified',
				'title'       => 'Recently Modified File',
				'description' => 'This file was modified within the last 14 days. Review it if you didn\'t make changes.',
				'location'    => self::relative_path( $f['path'] ),
				'snippet'     => 'Modified: ' . date( 'Y-m-d H:i:s', $f['mtime'] ),
				'pattern'     => 'mtime < 14 days',
				'dismissed'   => false,
			];
		}

		// Scan each directory
		foreach ( $dirs as [ $dir, $label, $php_only_flag ] ) {
			if ( ! is_dir( $dir ) ) continue;

			$php_ext   = $php_only_flag ? [ 'php' ] : [ 'php', 'js', 'html', 'htm' ];
			$files     = self::get_files( $dir, $php_ext, $php_only_flag ? 2 : 5 );

			foreach ( $files as $file ) {
				$files_scanned++;
				$contents = @file_get_contents( $file );
				if ( $contents === false || strlen( $contents ) > 2 * 1024 * 1024 ) continue; // skip >2MB

				// PHP in uploads = always critical
				if ( $php_only_flag && pathinfo( $file, PATHINFO_EXTENSION ) === 'php' ) {
					$findings[] = [
						'id'          => md5( 'php_in_uploads_' . $file ),
						'type'        => 'file',
						'severity'    => 'critical',
						'category'    => 'php_in_uploads',
						'title'       => 'PHP File in Uploads Folder',
						'description' => 'PHP files should never exist in wp-content/uploads. This is almost always a backdoor or webshell.',
						'location'    => self::relative_path( $file ),
						'snippet'     => substr( $contents, 0, 200 ),
						'pattern'     => '*.php in /uploads/',
						'dismissed'   => false,
					];
					continue;
				}

				// Pattern matching
				foreach ( self::$file_patterns as $key => [ $pattern, $severity, $description ] ) {
					if ( preg_match( $pattern, $contents, $m ) ) {
						$offset   = strpos( $contents, $m[0] );
						$line_num = $offset !== false ? substr_count( substr( $contents, 0, $offset ), "\n" ) + 1 : 0;
						$snippet  = trim( substr( $m[0], 0, 150 ) );

						$findings[] = [
							'id'          => md5( $key . $file ),
							'type'        => 'file',
							'severity'    => $severity,
							'category'    => 'malware',
							'title'       => self::pattern_title( $key ),
							'description' => $description,
							'location'    => self::relative_path( $file ) . ( $line_num ? " (line ~{$line_num})" : '' ),
							'snippet'     => $snippet,
							'pattern'     => $key,
							'dismissed'   => false,
						];
						break; // one finding per file per scan run is enough
					}
				}
			}
		}

		// Database scans
		global $wpdb;

		// Posts & pages
		$posts = $wpdb->get_results(
			"SELECT ID, post_title, post_content, post_type FROM {$wpdb->posts}
			WHERE post_status='publish' AND post_type IN ('post','page')
			LIMIT 500"
		);
		foreach ( $posts as $post ) {
			$db_scanned++;
			$haystack = $post->post_content;
			foreach ( self::$db_patterns as $key => [ $pattern, $severity, $description ] ) {
				if ( preg_match( $pattern, $haystack, $m ) ) {
					$findings[] = [
						'id'          => md5( $key . 'post' . $post->ID ),
						'type'        => 'database',
						'severity'    => $severity,
						'category'    => strpos( $key, 'pharma' ) !== false || strpos( $key, 'casino' ) !== false ? 'seo_injection' : 'db_injection',
						'title'       => self::pattern_title( $key ),
						'description' => $description,
						'location'    => "Post #{$post->ID}: " . esc_html( $post->post_title ) . " ({$post->post_type})",
						'snippet'     => trim( substr( $m[0], 0, 200 ) ),
						'pattern'     => $key,
						'dismissed'   => false,
					];
					break;
				}
			}
		}

		// Options table — high-value targets
		$option_names = [
			'widget_text', 'widget_custom_html', 'sidebars_widgets',
			'blogdescription', 'blogname', 'footer_scripts', 'header_scripts',
		];
		foreach ( $option_names as $opt ) {
			$val = get_option( $opt );
			if ( ! $val ) continue;
			$db_scanned++;
			$haystack = is_array( $val ) ? wp_json_encode( $val ) : (string) $val;
			foreach ( self::$db_patterns as $key => [ $pattern, $severity, $description ] ) {
				if ( preg_match( $pattern, $haystack, $m ) ) {
					$findings[] = [
						'id'          => md5( $key . 'option' . $opt ),
						'type'        => 'database',
						'severity'    => $severity,
						'category'    => 'db_injection',
						'title'       => self::pattern_title( $key ) . ' in Site Option',
						'description' => $description,
						'location'    => "wp_options → `{$opt}`",
						'snippet'     => trim( substr( $m[0], 0, 200 ) ),
						'pattern'     => $key,
						'dismissed'   => false,
					];
					break;
				}
			}
		}

		// Check for unknown admin users (created after site was last updated)
		$admins = get_users( [ 'role' => 'administrator' ] );
		$db_scanned += count( $admins );
		foreach ( $admins as $user ) {
			$registered = strtotime( $user->user_registered );
			$cutoff     = strtotime( '-30 days' );
			if ( $registered > $cutoff && $user->ID !== get_current_user_id() ) {
				$findings[] = [
					'id'          => md5( 'admin_user_' . $user->ID ),
					'type'        => 'database',
					'severity'    => 'warning',
					'category'    => 'suspicious_user',
					'title'       => 'Recently Created Admin Account',
					'description' => 'An administrator account was created in the last 30 days. Verify this was intentional.',
					'location'    => "User #{$user->ID}: {$user->user_login} ({$user->user_email})",
					'snippet'     => 'Registered: ' . $user->user_registered,
					'pattern'     => 'new_admin_user',
					'dismissed'   => false,
				];
			}
		}

		// Merge dismissed list
		$dismissed = get_option( 'fortress_dismissed_findings', [] );
		foreach ( $findings as &$f ) {
			if ( in_array( $f['id'], $dismissed, true ) ) {
				$f['dismissed'] = true;
			}
		}
		unset( $f );

		// Sort: critical first
		usort( $findings, function ( $a, $b ) {
			$order = [ 'critical' => 0, 'warning' => 1, 'info' => 2 ];
			$diff  = ( $order[ $a['severity'] ] ?? 2 ) - ( $order[ $b['severity'] ] ?? 2 );
			if ( $diff !== 0 ) return $diff;
			return (int) $b['dismissed'] - (int) $a['dismissed'];
		} );

		$result = [
			'scan_time'      => current_time( 'mysql' ),
			'files_scanned'  => $files_scanned,
			'db_scanned'     => $db_scanned,
			'findings'       => $findings,
			'critical_count' => count( array_filter( $findings, fn( $f ) => $f['severity'] === 'critical' && ! $f['dismissed'] ) ),
			'warning_count'  => count( array_filter( $findings, fn( $f ) => $f['severity'] === 'warning'  && ! $f['dismissed'] ) ),
			'info_count'     => count( array_filter( $findings, fn( $f ) => $f['severity'] === 'info'     && ! $f['dismissed'] ) ),
		];

		update_option( 'fortress_scan_results', $result, false );

		return $result;
	}

	/* ── Helpers ──────────────────────────────────────────────────────── */

	private static function get_files( string $dir, array $exts, int $max_depth = 5 ) : array {
		$files = [];
		try {
			$flags = FilesystemIterator::SKIP_DOTS | FilesystemIterator::FOLLOW_SYMLINKS;
			$iter  = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, $flags ),
				RecursiveIteratorIterator::SELF_FIRST
			);
			$iter->setMaxDepth( $max_depth );
			foreach ( $iter as $file ) {
				if ( ! $file->isFile() ) continue;
				if ( count( $files ) > 5000 ) break;
				if ( in_array( strtolower( $file->getExtension() ), $exts, true ) ) {
					$files[] = $file->getPathname();
				}
			}
		} catch ( Exception $e ) { /* unreadable dir */ }
		return $files;
	}

	private static function find_recently_modified( string $dir, int $days, array $exts, int $max_depth ) : array {
		$cutoff = time() - $days * DAY_IN_SECONDS;
		$recent = [];
		try {
			$flags = FilesystemIterator::SKIP_DOTS;
			$iter  = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, $flags ),
				RecursiveIteratorIterator::SELF_FIRST
			);
			$iter->setMaxDepth( $max_depth );
			foreach ( $iter as $file ) {
				if ( ! $file->isFile() ) continue;
				if ( count( $recent ) > 200 ) break;
				if ( ! in_array( strtolower( $file->getExtension() ), $exts, true ) ) continue;
				if ( $file->getMTime() >= $cutoff ) {
					$recent[] = [ 'path' => $file->getPathname(), 'mtime' => $file->getMTime() ];
				}
			}
		} catch ( Exception $e ) { /* skip */ }
		usort( $recent, fn( $a, $b ) => $b['mtime'] - $a['mtime'] );
		return array_slice( $recent, 0, 50 );
	}

	private static function relative_path( string $abs ) : string {
		return str_replace( ABSPATH, '/', $abs );
	}

	private static function pattern_title( string $key ) : string {
		$titles = [
			'eval_base64'       => 'Obfuscated Code (eval+base64)',
			'eval_gzip'         => 'Obfuscated Code (eval+gzip)',
			'eval_gzuncompress' => 'Obfuscated Code (eval+gzuncompress)',
			'eval_rot13'        => 'Obfuscated Code (eval+rot13)',
			'eval_hex'          => 'Obfuscated Code (eval+hex2bin)',
			'preg_replace_e'    => 'Dangerous preg_replace /e',
			'assert_input'      => 'Remote Code Execution (assert)',
			'create_function'   => 'Code Injection (create_function)',
			'shell_user_input'  => 'Shell Command Injection',
			'system_user_input' => 'OS Command Injection (system)',
			'passthru_input'    => 'OS Command Injection (passthru)',
			'exec_input'        => 'OS Command Injection (exec)',
			'move_upload'       => 'Unrestricted File Upload',
			'file_put_input'    => 'Arbitrary File Write',
			'base64_long'       => 'Suspicious Long Base64 String',
			'hex_string'        => 'Hex-Encoded String',
			'ob_callback'       => 'Output Buffer Callback',
			'globals_hex'       => 'Obfuscated Global Variable',
			'str_replace_array' => 'String Deobfuscation Pattern',
			'chr_concat'        => 'Character Concatenation Obfuscation',
			'wpconfig_access'   => 'wp-config.php Access Attempt',
			'remote_fopen'      => 'Remote File Inclusion (fopen)',
			'include_input'     => 'File Inclusion with User Input',
			'pharma_hack'       => 'Pharma Hack (SEO Spam)',
			'casino_spam'       => 'Casino/Gambling SEO Spam',
			'hidden_link'       => 'Hidden Link (SEO Spam)',
			'iframe_inject'     => 'Injected External iframe',
			'js_unescape'       => 'Obfuscated JavaScript (unescape)',
			'js_atob'           => 'Obfuscated JavaScript (atob)',
			'eval_script'       => 'JavaScript eval() Injection',
			'ext_script'        => 'External Script Tag',
			'spam_tld'          => 'Link to Suspicious Domain',
			'base64_decode_db'  => 'Encoded Content in Database',
			'wordpress_inject'  => 'SQL Injection in Stored Content',
		];
		return $titles[ $key ] ?? ucwords( str_replace( '_', ' ', $key ) );
	}
}
