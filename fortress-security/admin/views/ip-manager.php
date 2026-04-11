<?php
if ( ! defined( 'ABSPATH' ) ) exit;

$whitelist   = Fortress_DB::get_whitelist();
$current_ip  = Fortress_Logger::get_ip();
$wl_enabled  = get_option( 'fortress_ip_whitelist_enabled' );
$emergency   = get_option( 'fortress_emergency_token', '' );
$bypass_url  = add_query_arg( 'fortress_token', $emergency, admin_url( 'admin.php?page=fortress-security' ) );
?>
<div class="fortress-wrap">
	<?php include __DIR__ . '/partials/header.php'; ?>

	<?php if ( isset( $_GET['added'] ) )   : ?><div class="fort-notice success">IP address added to whitelist.</div><?php endif; ?>
	<?php if ( isset( $_GET['removed'] ) ) : ?><div class="fort-notice success">IP address removed from whitelist.</div><?php endif; ?>

	<?php if ( ! $wl_enabled ) : ?>
	<div class="fort-notice info">
		⚠️ IP Whitelisting is currently <strong>disabled</strong>. Enable it in <a href="<?php echo admin_url( 'admin.php?page=fortress-settings' ); ?>">Settings</a> to enforce admin access restrictions.
	</div>
	<?php endif; ?>

	<div class="fort-grid-2">

		<!-- Add new IP -->
		<div class="fort-card">
			<div class="fort-card-header"><h3>Add IP to Whitelist</h3></div>
			<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>" class="fort-form">
				<?php wp_nonce_field( 'fortress_add_ip' ); ?>
				<input type="hidden" name="action" value="fortress_add_ip">
				<div class="fort-form-row">
					<label>IP Address</label>
					<input type="text" name="ip_address" class="fort-input" placeholder="e.g. 203.0.113.10" required>
				</div>
				<div class="fort-form-row">
					<label>Label <span class="fort-optional">(optional)</span></label>
					<input type="text" name="label" class="fort-input" placeholder="e.g. Home, Office, VPN">
				</div>
				<div class="fort-form-row">
					<button type="submit" class="fort-btn blue">Add IP</button>
					<button type="button" class="fort-btn gray-outline" id="btn-use-my-ip" data-ip="<?php echo esc_attr( $current_ip ); ?>">
						Use My IP (<?php echo esc_html( $current_ip ); ?>)
					</button>
				</div>
			</form>
		</div>

		<!-- Emergency bypass -->
		<div class="fort-card fort-danger-card">
			<div class="fort-card-header"><h3>🔑 Emergency Bypass URL</h3></div>
			<?php if ( ! $wl_enabled ) : ?>
			<div class="fort-notice info" style="margin:12px 16px 0">
				ℹ️ The bypass URL only works when the <strong>IP Whitelist is enabled</strong>. It is not needed right now.
			</div>
			<?php endif; ?>
			<p class="fort-text-sm" style="padding-top:12px">If you accidentally lock yourself out, visit this URL from any IP to regain access. <strong>Keep this private.</strong></p>
			<div class="fort-copy-box" style="padding:0 20px 8px">
				<input type="text" id="bypass-url" class="fort-input" value="<?php echo esc_url( $bypass_url ); ?>" readonly>
				<button class="fort-btn blue" id="btn-copy-bypass">Copy</button>
			</div>
			<p class="fort-text-xs" style="color:#ef4444">⚠️ Anyone with this URL can access wp-admin. Do not share it.</p>
		</div>

	</div>

	<!-- Whitelist table -->
	<div class="fort-card">
		<div class="fort-card-header">
			<h3>Whitelisted IPs <span class="fort-count-badge"><?php echo count( $whitelist ); ?></span></h3>
		</div>
		<?php if ( empty( $whitelist ) ) : ?>
			<div class="fort-empty">
				No IPs whitelisted yet. Add your IP above before enabling the whitelist to avoid locking yourself out.
			</div>
		<?php else : ?>
			<table class="fort-table">
				<thead>
					<tr>
						<th>IP Address</th>
						<th>Label</th>
						<th>Added</th>
						<th>Status</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $whitelist as $entry ) :
					$is_current = ( $entry->ip_address === $current_ip );
				?>
					<tr>
						<td>
							<strong><?php echo esc_html( $entry->ip_address ); ?></strong>
							<?php if ( $is_current ) : ?><span class="fort-badge green" style="font-size:10px">YOU</span><?php endif; ?>
						</td>
						<td><?php echo esc_html( $entry->label ?: '—' ); ?></td>
						<td class="fort-time"><?php echo esc_html( date( 'M j, Y', strtotime( $entry->added_at ) ) ); ?></td>
						<td>
							<?php if ( $entry->is_active ) : ?>
								<span class="fort-badge green">Active</span>
							<?php else : ?>
								<span class="fort-badge gray">Disabled</span>
							<?php endif; ?>
						</td>
						<td class="fort-actions">
							<!-- Toggle -->
							<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>" style="display:inline">
								<?php wp_nonce_field( 'fortress_toggle_ip' ); ?>
								<input type="hidden" name="action"   value="fortress_toggle_ip">
								<input type="hidden" name="entry_id" value="<?php echo (int) $entry->id; ?>">
								<input type="hidden" name="active"   value="<?php echo $entry->is_active ? 0 : 1; ?>">
								<button type="submit" class="fort-btn-xs <?php echo $entry->is_active ? 'orange' : 'green'; ?>">
									<?php echo $entry->is_active ? 'Disable' : 'Enable'; ?>
								</button>
							</form>
							<!-- Remove -->
							<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>" style="display:inline" onsubmit="return confirm('Remove this IP from whitelist?')">
								<?php wp_nonce_field( 'fortress_remove_ip' ); ?>
								<input type="hidden" name="action"   value="fortress_remove_ip">
								<input type="hidden" name="entry_id" value="<?php echo (int) $entry->id; ?>">
								<button type="submit" class="fort-btn-xs red">Remove</button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>

</div>
