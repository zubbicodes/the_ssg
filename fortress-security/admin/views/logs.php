<?php
if ( ! defined( 'ABSPATH' ) ) exit;

$page       = max( 1, (int) ( $_GET['paged']      ?? 1 ) );
$ip_filter  = sanitize_text_field( $_GET['ip']         ?? '' );
$sus_filter = isset( $_GET['suspicious'] ) ? (string) $_GET['suspicious'] : '';
$blk_filter = isset( $_GET['blocked']    ) ? (string) $_GET['blocked']    : '';
$date_from  = sanitize_text_field( $_GET['date_from']  ?? '' );
$date_to    = sanitize_text_field( $_GET['date_to']    ?? '' );
$search     = sanitize_text_field( $_GET['search']     ?? '' );
$per_page   = 50;

$result = Fortress_DB::get_logs( [
	'per_page'   => $per_page,
	'page'       => $page,
	'ip'         => $ip_filter,
	'suspicious' => $sus_filter,
	'blocked'    => $blk_filter,
	'date_from'  => $date_from,
	'date_to'    => $date_to,
	'search'     => $search,
] );

$total      = $result['total'];
$rows       = $result['rows'];
$total_pages = max( 1, ceil( $total / $per_page ) );
$base_url   = admin_url( 'admin.php?page=fortress-logs' );

function fort_logs_url( array $extra = [] ) : string {
	$params = array_filter( array_merge( [
		'page'       => 'fortress-logs',
		'ip'         => $_GET['ip']         ?? '',
		'suspicious' => $_GET['suspicious'] ?? '',
		'blocked'    => $_GET['blocked']    ?? '',
		'date_from'  => $_GET['date_from']  ?? '',
		'date_to'    => $_GET['date_to']    ?? '',
		'search'     => $_GET['search']     ?? '',
	], $extra ) );
	return admin_url( 'admin.php?' . http_build_query( $params ) );
}
?>
<div class="fortress-wrap">
	<?php include __DIR__ . '/partials/header.php'; ?>

	<?php if ( isset( $_GET['cleared'] ) ) : ?>
		<div class="fort-notice success">All logs have been cleared.</div>
	<?php endif; ?>

	<div class="fort-card">
		<div class="fort-card-header">
			<h3>Traffic Logs <span class="fort-count-badge"><?php echo number_format( $total ); ?></span></h3>
			<div class="fort-header-actions">
				<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>" style="display:inline" onsubmit="return confirm('Clear ALL log entries? This cannot be undone.')">
					<?php wp_nonce_field( 'fortress_clear_logs' ); ?>
					<input type="hidden" name="action" value="fortress_clear_logs">
					<button type="submit" class="fort-btn red-outline">Clear All Logs</button>
				</form>
				<a href="<?php echo $base_url; ?>" class="fort-btn gray-outline">Reset Filters</a>
			</div>
		</div>

		<!-- Filters -->
		<form method="get" class="fort-filter-bar">
			<input type="hidden" name="page" value="fortress-logs">
			<input type="text"   name="ip"        class="fort-input-sm" placeholder="Filter IP..." value="<?php echo esc_attr( $ip_filter ); ?>">
			<input type="text"   name="search"    class="fort-input-sm" placeholder="Search URI / UA..." value="<?php echo esc_attr( $search ); ?>">
			<input type="date"   name="date_from" class="fort-input-sm" value="<?php echo esc_attr( $date_from ); ?>">
			<input type="date"   name="date_to"   class="fort-input-sm" value="<?php echo esc_attr( $date_to ); ?>">
			<select name="suspicious" class="fort-select-sm">
				<option value="">All requests</option>
				<option value="1" <?php selected( $sus_filter, '1' ); ?>>Suspicious only</option>
				<option value="0" <?php selected( $sus_filter, '0' ); ?>>Clean only</option>
			</select>
			<select name="blocked" class="fort-select-sm">
				<option value="">All statuses</option>
				<option value="1" <?php selected( $blk_filter, '1' ); ?>>Blocked only</option>
				<option value="0" <?php selected( $blk_filter, '0' ); ?>>Allowed only</option>
			</select>
			<button type="submit" class="fort-btn blue">Filter</button>
		</form>

		<!-- Table -->
		<div class="fort-table-wrap">
		<?php if ( empty( $rows ) ) : ?>
			<div class="fort-empty">No log entries found matching your filters.</div>
		<?php else : ?>
			<table class="fort-table fort-logs-table">
				<thead>
					<tr>
						<th>Time</th>
						<th>IP</th>
						<th>Method</th>
						<th>URI</th>
						<th>Threat</th>
						<th>Score</th>
						<th>Status</th>
						<th>User Agent</th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $rows as $row ) :
					$is_sus = (int) $row->is_suspicious;
					$is_blk = (int) $row->blocked;
					$row_class = $is_blk ? 'row-blocked' : ( $is_sus ? 'row-sus' : '' );
				?>
					<tr class="<?php echo $row_class; ?>">
						<td class="fort-time" title="<?php echo esc_attr( $row->log_time ); ?>">
							<?php echo esc_html( date( 'M j, H:i:s', strtotime( $row->log_time ) ) ); ?>
						</td>
						<td>
							<a href="<?php echo esc_url( fort_logs_url( [ 'ip' => $row->ip_address, 'paged' => 1 ] ) ); ?>" class="fort-ip-link">
								<?php echo esc_html( $row->ip_address ); ?>
							</a>
						</td>
						<td><span class="fort-method <?php echo strtolower( $row->request_method ); ?>"><?php echo esc_html( $row->request_method ); ?></span></td>
						<td class="fort-uri" title="<?php echo esc_attr( $row->request_uri ); ?>">
							<?php echo esc_html( mb_substr( $row->request_uri, 0, 80 ) ); ?>
						</td>
						<td>
							<?php if ( $row->threat_type ) : ?>
								<?php foreach ( explode( ',', $row->threat_type ) as $t ) : ?>
									<span class="fort-threat-tag"><?php echo esc_html( str_replace( '_', ' ', trim( $t ) ) ); ?></span>
								<?php endforeach; ?>
							<?php else : ?>
								<span class="fort-clean-tag">Clean</span>
							<?php endif; ?>
						</td>
						<td>
							<?php
							$sc = (int) $row->threat_score;
							if ( $sc >= 60 )      echo "<span class='fort-score high'>{$sc}</span>";
							elseif ( $sc >= 30 )  echo "<span class='fort-score med'>{$sc}</span>";
							elseif ( $sc > 0 )    echo "<span class='fort-score low'>{$sc}</span>";
							else                  echo '—';
							?>
						</td>
						<td>
							<?php if ( $is_blk ) : ?>
								<span class="fort-badge red">Blocked</span>
							<?php elseif ( $is_sus ) : ?>
								<span class="fort-badge orange">Flagged</span>
							<?php else : ?>
								<span class="fort-badge green">OK</span>
							<?php endif; ?>
						</td>
						<td class="fort-ua" title="<?php echo esc_attr( $row->user_agent ); ?>">
							<?php echo esc_html( mb_substr( $row->user_agent, 0, 50 ) ); ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		</div>

		<!-- Pagination -->
		<?php if ( $total_pages > 1 ) : ?>
		<div class="fort-pagination">
			<?php if ( $page > 1 ) : ?>
				<a href="<?php echo esc_url( fort_logs_url( [ 'paged' => $page - 1 ] ) ); ?>" class="fort-page-btn">← Prev</a>
			<?php endif; ?>
			<span class="fort-page-info">Page <?php echo $page; ?> of <?php echo $total_pages; ?> (<?php echo number_format( $total ); ?> entries)</span>
			<?php if ( $page < $total_pages ) : ?>
				<a href="<?php echo esc_url( fort_logs_url( [ 'paged' => $page + 1 ] ) ); ?>" class="fort-page-btn">Next →</a>
			<?php endif; ?>
		</div>
		<?php endif; ?>

	</div><!-- /.fort-card -->
</div>
