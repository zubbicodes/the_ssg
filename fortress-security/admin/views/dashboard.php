<?php
if ( ! defined( 'ABSPATH' ) ) exit;

$stats    = Fortress_DB::get_stats();
$enabled  = get_option( 'fortress_enabled' );
$reg_lock = get_option( 'fortress_reg_lock' );
$wl_on    = get_option( 'fortress_ip_whitelist_enabled' );
$log_on   = get_option( 'fortress_logging_enabled' );
$discord  = get_option( 'fortress_discord_enabled' );
?>
<div class="fortress-wrap">

	<?php include __DIR__ . '/partials/header.php'; ?>

	<!-- Status bar -->
	<div class="fort-statusbar">
		<div class="fort-status-pill <?php echo $enabled ? 'active' : 'inactive'; ?>">
			<span class="fort-dot"></span>
			<?php echo $enabled ? 'Protection Active' : 'Protection Disabled'; ?>
		</div>
		<div class="fort-status-badges">
			<span class="fort-badge <?php echo $reg_lock ? 'on' : 'off'; ?>"><?php echo $reg_lock ? '🔒 Reg Lock ON' : '🔓 Reg Lock OFF'; ?></span>
			<span class="fort-badge <?php echo $wl_on   ? 'on' : 'off'; ?>"><?php echo $wl_on   ? '✅ IP Whitelist ON' : '⚪ IP Whitelist OFF'; ?></span>
			<span class="fort-badge <?php echo $log_on  ? 'on' : 'off'; ?>"><?php echo $log_on  ? '📋 Logging ON' : '📋 Logging OFF'; ?></span>
			<span class="fort-badge <?php echo $discord ? 'on' : 'off'; ?>"><?php echo $discord ? '🔔 Discord ON' : '🔕 Discord OFF'; ?></span>
		</div>
	</div>

	<!-- Stat cards -->
	<div class="fort-grid-4">
		<div class="fort-card fort-stat-card">
			<div class="fort-stat-icon blue">📥</div>
			<div class="fort-stat-body">
				<div class="fort-stat-num" id="stat-total"><?php echo number_format( $stats['total_today'] ); ?></div>
				<div class="fort-stat-label">Requests Today</div>
			</div>
		</div>
		<div class="fort-card fort-stat-card">
			<div class="fort-stat-icon orange">⚠️</div>
			<div class="fort-stat-body">
				<div class="fort-stat-num" id="stat-sus"><?php echo number_format( $stats['suspicious_today'] ); ?></div>
				<div class="fort-stat-label">Suspicious Today</div>
			</div>
		</div>
		<div class="fort-card fort-stat-card">
			<div class="fort-stat-icon red">🚫</div>
			<div class="fort-stat-body">
				<div class="fort-stat-num" id="stat-blocked"><?php echo number_format( $stats['blocked_today'] ); ?></div>
				<div class="fort-stat-label">Blocked Today</div>
			</div>
		</div>
		<div class="fort-card fort-stat-card">
			<div class="fort-stat-icon gray">📊</div>
			<div class="fort-stat-body">
				<div class="fort-stat-num"><?php echo number_format( $stats['total_all'] ); ?></div>
				<div class="fort-stat-label">Total Logged</div>
			</div>
		</div>
	</div>

	<div class="fort-grid-2">

		<!-- Recent Threats -->
		<div class="fort-card">
			<div class="fort-card-header">
				<h3>Recent Threats</h3>
				<a href="<?php echo admin_url( 'admin.php?page=fortress-logs&suspicious=1' ); ?>" class="fort-link-sm">View all →</a>
			</div>
			<?php if ( empty( $stats['recent_threats'] ) ) : ?>
				<div class="fort-empty">No threats detected recently.</div>
			<?php else : ?>
				<table class="fort-table">
					<thead><tr>
						<th>IP</th><th>Type</th><th>Score</th><th>Time</th>
					</tr></thead>
					<tbody>
					<?php foreach ( $stats['recent_threats'] as $row ) : ?>
						<tr>
							<td><a href="<?php echo admin_url( 'admin.php?page=fortress-logs&ip=' . esc_attr( $row->ip_address ) ); ?>" class="fort-ip-link"><?php echo esc_html( $row->ip_address ); ?></a></td>
							<td><?php echo '<span class="fort-threat-tag">' . esc_html( str_replace( '_', ' ', explode( ',', $row->threat_type )[0] ) ) . '</span>'; ?></td>
							<td><?php echo self_score_badge( (int) $row->threat_score ); ?></td>
							<td class="fort-time"><?php echo esc_html( human_time_diff( strtotime( $row->log_time ), current_time( 'timestamp' ) ) ) . ' ago'; ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>

		<!-- Top IPs today -->
		<div class="fort-card">
			<div class="fort-card-header">
				<h3>Top IPs Today</h3>
			</div>
			<?php if ( empty( $stats['top_ips'] ) ) : ?>
				<div class="fort-empty">No traffic recorded today.</div>
			<?php else : ?>
				<table class="fort-table">
					<thead><tr><th>IP Address</th><th>Requests</th><th></th></tr></thead>
					<tbody>
					<?php foreach ( $stats['top_ips'] as $row ) : ?>
						<tr>
							<td><a href="<?php echo admin_url( 'admin.php?page=fortress-logs&ip=' . esc_attr( $row->ip_address ) ); ?>" class="fort-ip-link"><?php echo esc_html( $row->ip_address ); ?></a></td>
							<td><?php echo number_format( $row->hits ); ?></td>
							<td>
								<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=fortress_add_ip&ip_address=' . urlencode( $row->ip_address ) . '&label=Auto+added' ), 'fortress_add_ip' ); ?>" class="fort-btn-xs" title="Add to whitelist">+ WL</a>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>

		<!-- Threat breakdown -->
		<div class="fort-card">
			<div class="fort-card-header">
				<h3>Threat Breakdown</h3>
			</div>
			<?php if ( empty( $stats['threat_breakdown'] ) ) : ?>
				<div class="fort-empty">No threat data yet.</div>
			<?php else : ?>
				<div class="fort-bar-list">
				<?php
				$max = max( array_column( (array) $stats['threat_breakdown'], 'cnt' ) );
				foreach ( $stats['threat_breakdown'] as $row ) :
					$pct = $max > 0 ? round( ( $row->cnt / $max ) * 100 ) : 0;
				?>
					<div class="fort-bar-row">
						<span class="fort-bar-label"><?php echo esc_html( str_replace( '_', ' ', $row->threat_type ) ); ?></span>
						<div class="fort-bar-track"><div class="fort-bar-fill" style="width:<?php echo $pct; ?>%"></div></div>
						<span class="fort-bar-count"><?php echo number_format( $row->cnt ); ?></span>
					</div>
				<?php endforeach; ?>
				</div>
			<?php endif; ?>
		</div>

		<!-- Quick actions -->
		<div class="fort-card">
			<div class="fort-card-header"><h3>Quick Actions</h3></div>
			<div class="fort-action-list">
				<a href="<?php echo admin_url( 'admin.php?page=fortress-ip-manager' ); ?>" class="fort-action-btn blue">
					<span>🛡️</span> Manage IP Whitelist
				</a>
				<a href="<?php echo admin_url( 'admin.php?page=fortress-logs' ); ?>" class="fort-action-btn gray">
					<span>📋</span> View All Logs
				</a>
				<a href="<?php echo admin_url( 'admin.php?page=fortress-settings' ); ?>" class="fort-action-btn gray">
					<span>⚙️</span> Settings
				</a>
				<a href="<?php echo admin_url( 'admin.php?page=fortress-logs&suspicious=1' ); ?>" class="fort-action-btn orange">
					<span>⚠️</span> Suspicious Requests
				</a>
				<a href="<?php echo admin_url( 'admin.php?page=fortress-logs&blocked=1' ); ?>" class="fort-action-btn red">
					<span>🚫</span> Blocked Requests
				</a>
			</div>
		</div>

	</div><!-- /.fort-grid-2 -->

</div><!-- /.fortress-wrap -->

<?php
function self_score_badge( int $score ) : string {
	if ( $score >= 60 ) return "<span class='fort-score high'>{$score}</span>";
	if ( $score >= 30 ) return "<span class='fort-score med'>{$score}</span>";
	return "<span class='fort-score low'>{$score}</span>";
}
?>
