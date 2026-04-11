<?php
if ( ! defined( 'ABSPATH' ) ) exit;

$results   = get_option( 'fortress_scan_results', null );
$dismissed = get_option( 'fortress_dismissed_findings', [] );

$severity_icons = [
	'critical' => '🔴',
	'warning'  => '🟠',
	'info'     => '🔵',
];
$category_labels = [
	'malware'           => 'Malware / Backdoor',
	'php_in_uploads'    => 'PHP in Uploads',
	'seo_injection'     => 'SEO Injection',
	'db_injection'      => 'DB Injection',
	'recently_modified' => 'Recently Modified',
	'suspicious_user'   => 'Suspicious User',
];
?>
<div class="fortress-wrap">
	<?php include __DIR__ . '/partials/header.php'; ?>

	<!-- Scan launcher -->
	<div class="fort-card fort-scan-hero">
		<div class="fort-scan-hero-left">
			<div class="fort-scan-title">🔍 Security Scanner</div>
			<div class="fort-scan-sub">
				Scans theme files, plugin files, uploads folder, database content, and WordPress options for malware, backdoors, SEO injection, and suspicious code.
			</div>
			<?php if ( $results ) : ?>
			<div class="fort-scan-meta">
				Last scan: <strong><?php echo esc_html( $results['scan_time'] ); ?></strong>
				&nbsp;·&nbsp; <?php echo (int) $results['files_scanned']; ?> files
				&nbsp;·&nbsp; <?php echo (int) $results['db_scanned']; ?> DB rows
			</div>
			<?php endif; ?>
		</div>
		<div class="fort-scan-hero-right">
			<button id="btn-run-scan" class="fort-btn blue fort-btn-lg">
				<span id="scan-btn-text">▶ Run Scan</span>
			</button>
			<div class="fort-scan-scope">
				<label><input type="radio" name="scan_scope" value="full" checked> Full scan</label>
				<label><input type="radio" name="scan_scope" value="quick"> Quick (theme + uploads only)</label>
			</div>
		</div>
	</div>

	<!-- Progress -->
	<div id="scan-progress" style="display:none" class="fort-card fort-scan-progress">
		<div class="fort-scan-spinner"></div>
		<div>
			<strong>Scanning…</strong>
			<div class="fort-scan-progress-sub">This may take up to 60 seconds on large sites. Please wait.</div>
		</div>
	</div>

	<!-- Results -->
	<?php if ( $results ) :
		$active = array_filter( $results['findings'], fn( $f ) => ! $f['dismissed'] );
		$hidden = array_filter( $results['findings'], fn( $f ) =>   $f['dismissed'] );
		$critical = array_filter( $active, fn( $f ) => $f['severity'] === 'critical' );
		$warnings = array_filter( $active, fn( $f ) => $f['severity'] === 'warning' );
		$infos    = array_filter( $active, fn( $f ) => $f['severity'] === 'info' );
	?>

	<!-- Summary bar -->
	<div class="fort-grid-4" style="margin-bottom:20px">
		<div class="fort-card fort-stat-card" style="border-left:4px solid #ef4444">
			<div class="fort-stat-icon red">🔴</div>
			<div class="fort-stat-body">
				<div class="fort-stat-num"><?php echo count( $critical ); ?></div>
				<div class="fort-stat-label">Critical</div>
			</div>
		</div>
		<div class="fort-card fort-stat-card" style="border-left:4px solid #f97316">
			<div class="fort-stat-icon orange">🟠</div>
			<div class="fort-stat-body">
				<div class="fort-stat-num"><?php echo count( $warnings ); ?></div>
				<div class="fort-stat-label">Warnings</div>
			</div>
		</div>
		<div class="fort-card fort-stat-card" style="border-left:4px solid #3b82f6">
			<div class="fort-stat-icon blue">🔵</div>
			<div class="fort-stat-body">
				<div class="fort-stat-num"><?php echo count( $infos ); ?></div>
				<div class="fort-stat-label">Info</div>
			</div>
		</div>
		<div class="fort-card fort-stat-card" style="border-left:4px solid #22c55e">
			<div class="fort-stat-icon gray">✅</div>
			<div class="fort-stat-body">
				<div class="fort-stat-num"><?php echo count( $hidden ); ?></div>
				<div class="fort-stat-label">Dismissed</div>
			</div>
		</div>
	</div>

	<?php if ( empty( $active ) ) : ?>
		<div class="fort-card">
			<div class="fort-empty" style="padding:48px">
				✅ <strong>No active issues found.</strong><br>
				<span style="color:#94a3b8">Your site looks clean based on the last scan.</span>
			</div>
		</div>
	<?php else : ?>

	<!-- Findings list -->
	<div class="fort-card" id="scan-results-card">
		<div class="fort-card-header">
			<h3>Findings <span class="fort-count-badge"><?php echo count( $active ); ?></span></h3>
			<div class="fort-header-actions">
				<button class="fort-btn gray-outline fort-btn-sm" id="btn-filter-all"      data-filter="">All</button>
				<button class="fort-btn gray-outline fort-btn-sm" id="btn-filter-critical" data-filter="critical">Critical</button>
				<button class="fort-btn gray-outline fort-btn-sm" id="btn-filter-warning"  data-filter="warning">Warnings</button>
				<button class="fort-btn gray-outline fort-btn-sm" id="btn-filter-file"     data-filter-type="file">Files</button>
				<button class="fort-btn gray-outline fort-btn-sm" id="btn-filter-db"       data-filter-type="database">Database</button>
			</div>
		</div>

		<div id="findings-list">
		<?php foreach ( $active as $f ) :
			$sev_class = 'finding-' . $f['severity'];
		?>
			<div class="fort-finding <?php echo $sev_class; ?>" data-id="<?php echo esc_attr( $f['id'] ); ?>" data-severity="<?php echo esc_attr( $f['severity'] ); ?>" data-type="<?php echo esc_attr( $f['type'] ); ?>">
				<div class="fort-finding-header">
					<div class="fort-finding-meta">
						<span class="fort-finding-sev <?php echo esc_attr( $f['severity'] ); ?>">
							<?php echo $severity_icons[ $f['severity'] ] ?? '⚪'; ?> <?php echo ucfirst( $f['severity'] ); ?>
						</span>
						<span class="fort-finding-cat"><?php echo esc_html( $category_labels[ $f['category'] ] ?? ucwords( str_replace( '_', ' ', $f['category'] ) ) ); ?></span>
						<span class="fort-finding-source"><?php echo $f['type'] === 'file' ? '📄 File' : '🗄️ Database'; ?></span>
					</div>
					<div class="fort-finding-actions">
						<button class="fort-btn-xs gray btn-dismiss-finding" data-id="<?php echo esc_attr( $f['id'] ); ?>">Dismiss</button>
					</div>
				</div>
				<div class="fort-finding-body">
					<div class="fort-finding-title"><?php echo esc_html( $f['title'] ); ?></div>
					<div class="fort-finding-desc"><?php echo esc_html( $f['description'] ); ?></div>
					<div class="fort-finding-location">
						<span class="fort-loc-label">Location:</span>
						<code><?php echo esc_html( $f['location'] ); ?></code>
					</div>
					<?php if ( ! empty( $f['snippet'] ) ) : ?>
					<div class="fort-finding-snippet">
						<span class="fort-loc-label">Matched:</span>
						<pre><?php echo esc_html( $f['snippet'] ); ?></pre>
					</div>
					<?php endif; ?>
				</div>
			</div>
		<?php endforeach; ?>
		</div>
	</div>
	<?php endif; ?>

	<!-- Dismissed findings (collapsed) -->
	<?php if ( ! empty( $hidden ) ) : ?>
	<details class="fort-dismissed-section">
		<summary>Dismissed Findings (<?php echo count( $hidden ); ?>)</summary>
		<div class="fort-card" style="margin-top:8px">
		<?php foreach ( $hidden as $f ) : ?>
			<div class="fort-finding finding-dismissed">
				<div class="fort-finding-header">
					<div class="fort-finding-meta">
						<span style="color:#94a3b8"><?php echo $severity_icons[ $f['severity'] ] ?? '⚪'; ?> <?php echo esc_html( $f['title'] ); ?></span>
						<code style="font-size:11px;color:#94a3b8"><?php echo esc_html( $f['location'] ); ?></code>
					</div>
					<button class="fort-btn-xs green btn-undismiss-finding" data-id="<?php echo esc_attr( $f['id'] ); ?>">Restore</button>
				</div>
			</div>
		<?php endforeach; ?>
		</div>
	</details>
	<?php endif; ?>

	<?php endif; // end if results ?>

	<?php if ( ! $results ) : ?>
	<div class="fort-card">
		<div class="fort-empty" style="padding:64px">
			<div style="font-size:40px;margin-bottom:12px">🔍</div>
			<strong>No scan has been run yet.</strong><br>
			<span style="color:#94a3b8">Click "Run Scan" above to scan your site for threats.</span>
		</div>
	</div>
	<?php endif; ?>

</div>
