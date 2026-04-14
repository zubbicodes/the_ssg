<?php
if ( ! defined( 'ABSPATH' ) ) exit;

$blacklist    = Fortress_DB::get_blacklist();
$usr_wl       = Fortress_DB::get_username_whitelist();
$whitelist     = Fortress_DB::get_whitelist();
$current_ip    = Fortress_Logger::get_ip();
$fw_enabled    = get_option( 'fortress_firewall_enabled', 1 );
$uw_enabled    = get_option( 'fortress_username_whitelist_enabled', 0 );
?>
<div class="fortress-wrap">
	<?php include __DIR__ . '/partials/header.php'; ?>

	<?php if ( isset( $_GET['bl_added'] ) )   : ?><div class="fort-notice success">✅ IP added to blacklist — they will be blocked site-wide.</div><?php endif; ?>
	<?php if ( isset( $_GET['bl_removed'] ) ) : ?><div class="fort-notice success">🗑️ IP removed from blacklist.</div><?php endif; ?>
	<?php if ( isset( $_GET['uw_added'] ) )   : ?><div class="fort-notice success">✅ Username added to whitelist.</div><?php endif; ?>
	<?php if ( isset( $_GET['uw_removed'] ) ) : ?><div class="fort-notice success">🗑️ Username removed from whitelist.</div><?php endif; ?>

	<!-- ================================================================
	     SECTION 1 — Firewall status bar
	     ================================================================ -->
	<div class="fort-grid-2" style="margin-bottom:20px">
		<div class="fort-card" style="border-left:4px solid <?php echo $fw_enabled ? '#22c55e' : '#ef4444'; ?>">
			<div class="fort-card-header">
				<h3>🔥 IP Firewall (Blacklist)</h3>
				<span class="fort-badge <?php echo $fw_enabled ? 'green' : 'red'; ?>" style="font-size:13px">
					<?php echo $fw_enabled ? 'Active' : 'Disabled'; ?>
				</span>
			</div>
			<p class="fort-text-sm" style="padding:0 20px 12px">
				Blacklisted IPs are blocked <strong>on every request</strong> across the entire site.
				Toggle in <a href="<?php echo admin_url( 'admin.php?page=fortress-settings' ); ?>">Settings</a>.
			</p>
		</div>
		<div class="fort-card" style="border-left:4px solid <?php echo $uw_enabled ? '#22c55e' : '#f59e0b'; ?>">
			<div class="fort-card-header">
				<h3>🛡️ Username Whitelist</h3>
				<span class="fort-badge <?php echo $uw_enabled ? 'green' : 'orange'; ?>" style="font-size:13px">
					<?php echo $uw_enabled ? 'Active' : 'Disabled'; ?>
				</span>
			</div>
			<p class="fort-text-sm" style="padding:0 20px 12px">
				When active, <strong>only whitelisted usernames</strong> can attempt to log in.
				Any other username causes an <strong>instant IP block</strong>.
				<?php if ( ! $uw_enabled ) : ?>
					<br><a href="<?php echo admin_url( 'admin.php?page=fortress-settings' ); ?>">Enable in Settings →</a>
				<?php endif; ?>
			</p>
		</div>
	</div>

	<!-- ================================================================
	     SECTION 2 — IP Blacklist
	     ================================================================ -->
	<div class="fort-card" style="margin-bottom:24px">
		<div class="fort-card-header">
			<h3>🚫 IP Blacklist <span class="fort-count-badge"><?php echo count( $blacklist ); ?></span></h3>
			<span class="fort-text-xs" style="color:#94a3b8">These IPs are blocked everywhere, including the front-end.</span>
		</div>

		<!-- Add form -->
		<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>" class="fort-form" style="padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.07)">
			<?php wp_nonce_field( 'fortress_add_blacklist' ); ?>
			<input type="hidden" name="action" value="fortress_add_blacklist">
			<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
				<div class="fort-form-row" style="margin:0;flex:1;min-width:170px">
					<label>IP Address <span style="color:#ef4444">*</span></label>
					<input type="text" name="ip_address" class="fort-input" placeholder="e.g. 203.0.113.99" required>
				</div>
				<div class="fort-form-row" style="margin:0;flex:1;min-width:180px">
					<label>Label <span class="fort-optional">(optional)</span></label>
					<input type="text" name="label" class="fort-input" placeholder="e.g. Known attacker, Bot farm">
				</div>
				<div class="fort-form-row" style="margin:0">
					<label>&nbsp;</label>
					<button type="submit" class="fort-btn red">🚫 Blacklist IP</button>
				</div>
				<div class="fort-form-row" style="margin:0">
					<label>&nbsp;</label>
					<button type="button" class="fort-btn gray-outline" id="btn-bl-my-ip" data-ip="<?php echo esc_attr( $current_ip ); ?>" title="Add your current IP">
						My IP (<?php echo esc_html( $current_ip ); ?>)
					</button>
				</div>
			</div>
		</form>

		<!-- Table -->
		<?php if ( empty( $blacklist ) ) : ?>
			<div class="fort-empty">No IPs are blacklisted. Add one above to start blocking attackers.</div>
		<?php else : ?>
			<div class="fort-table-wrap">
				<table class="fort-table">
					<thead>
						<tr>
							<th>#</th>
							<th>IP Address</th>
							<th>Label / Reason</th>
							<th>Blocked Since</th>
							<th>Expires</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $blacklist as $entry ) : ?>
						<tr>
							<td class="fort-time"><?php echo (int) $entry->id; ?></td>
							<td>
								<strong><?php echo esc_html( $entry->ip_address ); ?></strong>
								<?php if ( $entry->ip_address === $current_ip ) : ?>
									<span class="fort-badge orange" style="font-size:10px">YOU</span>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( $entry->label ?: '—' ); ?></td>
							<td class="fort-time"><?php echo esc_html( date( 'M j, Y H:i', strtotime( $entry->added_at ) ) ); ?></td>
							<td><?php echo $entry->expires_at ? esc_html( date( 'M j, Y', strtotime( $entry->expires_at ) ) ) : '<span style="color:#94a3b8">Permanent</span>'; ?></td>
							<td class="fort-actions">
								<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>" style="display:inline"
								      onsubmit="return confirm('Remove <?php echo esc_attr( $entry->ip_address ); ?> from blacklist?')">
									<?php wp_nonce_field( 'fortress_remove_blacklist' ); ?>
									<input type="hidden" name="action"   value="fortress_remove_blacklist">
									<input type="hidden" name="entry_id" value="<?php echo (int) $entry->id; ?>">
									<button type="submit" class="fort-btn-xs red">Unblock</button>
								</form>
								<a href="<?php echo esc_url( add_query_arg( [ 'page' => 'fortress-logs', 'ip' => $entry->ip_address ], admin_url( 'admin.php' ) ) ); ?>"
								   class="fort-btn-xs gray">View Logs</a>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>

	<!-- ================================================================
	     SECTION 3 — Username Whitelist
	     ================================================================ -->
	<div class="fort-card" style="margin-bottom:24px">
		<div class="fort-card-header">
			<h3>👤 Login Username Whitelist <span class="fort-count-badge"><?php echo count( $usr_wl ); ?></span></h3>
			<span class="fort-text-xs" style="color:#94a3b8">Only these usernames may attempt to log in. Anyone else → instant IP block.</span>
		</div>

		<?php if ( ! $uw_enabled ) : ?>
			<div class="fort-notice info" style="margin:12px 20px 0">
				⚠️ Username whitelisting is currently <strong>disabled</strong>.
				<a href="<?php echo admin_url( 'admin.php?page=fortress-settings' ); ?>">Enable it in Settings</a> — but make sure to add your own username first!
			</div>
		<?php endif; ?>

		<?php if ( $uw_enabled && count( $usr_wl ) === 0 ) : ?>
			<div class="fort-notice info" style="margin:12px 20px 0">
				⚠️ The username whitelist is <strong>enabled but empty</strong> — enforcement is suspended until you add at least one username to prevent a lockout.
			</div>
		<?php endif; ?>

		<!-- Add form -->
		<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>" class="fort-form" style="padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.07)">
			<?php wp_nonce_field( 'fortress_add_username_wl' ); ?>
			<input type="hidden" name="action" value="fortress_add_username_wl">
			<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
				<div class="fort-form-row" style="margin:0;flex:1;min-width:160px">
					<label>WordPress Username <span style="color:#22c55e">*</span></label>
					<input type="text" name="username" class="fort-input" placeholder="e.g. admin, john_doe" required
					       autocomplete="new-password">
				</div>
				<div class="fort-form-row" style="margin:0;flex:1;min-width:180px">
					<label>Label <span class="fort-optional">(optional)</span></label>
					<input type="text" name="label" class="fort-input" placeholder="e.g. Site admin, Editor">
				</div>
				<div class="fort-form-row" style="margin:0">
					<label>&nbsp;</label>
					<button type="submit" class="fort-btn green">✅ Allow Username</button>
				</div>
				<div class="fort-form-row" style="margin:0">
					<label>&nbsp;</label>
					<button type="button" class="fort-btn gray-outline" id="btn-wl-my-username"
					        data-username="<?php echo esc_attr( wp_get_current_user()->user_login ); ?>">
						Add Mine (<?php echo esc_html( wp_get_current_user()->user_login ); ?>)
					</button>
				</div>
			</div>
		</form>

		<!-- Table -->
		<?php if ( empty( $usr_wl ) ) : ?>
			<div class="fort-empty">No usernames whitelisted yet. Add yours above before enabling this feature.</div>
		<?php else : ?>
			<div class="fort-table-wrap">
				<table class="fort-table">
					<thead>
						<tr>
							<th>#</th>
							<th>Username</th>
							<th>Label</th>
							<th>Added</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $usr_wl as $u ) : ?>
						<tr>
							<td class="fort-time"><?php echo (int) $u->id; ?></td>
							<td>
								<strong><?php echo esc_html( $u->username ); ?></strong>
								<?php if ( $u->username === wp_get_current_user()->user_login ) : ?>
									<span class="fort-badge green" style="font-size:10px">YOU</span>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( $u->label ?: '—' ); ?></td>
							<td class="fort-time"><?php echo esc_html( date( 'M j, Y', strtotime( $u->added_at ) ) ); ?></td>
							<td class="fort-actions">
								<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>" style="display:inline"
								      onsubmit="return confirm('Remove username &quot;<?php echo esc_attr( $u->username ); ?>&quot; from whitelist?')">
									<?php wp_nonce_field( 'fortress_remove_username_wl' ); ?>
									<input type="hidden" name="action"   value="fortress_remove_username_wl">
									<input type="hidden" name="entry_id" value="<?php echo (int) $u->id; ?>">
									<button type="submit" class="fort-btn-xs red">Remove</button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>

	<!-- ================================================================
	     SECTION 4 — IP Whitelist (reference, managed on IP Manager page)
	     ================================================================ -->
	<div class="fort-card">
		<div class="fort-card-header">
			<h3>✅ Admin IP Whitelist <span class="fort-count-badge"><?php echo count( $whitelist ); ?></span></h3>
			<a href="<?php echo admin_url( 'admin.php?page=fortress-ip-manager' ); ?>" class="fort-btn blue" style="font-size:12px">
				Manage on IP Manager →
			</a>
		</div>
		<?php if ( empty( $whitelist ) ) : ?>
			<div class="fort-empty">No IPs whitelisted. Use the IP Manager to add trusted admin IPs.</div>
		<?php else : ?>
			<div class="fort-table-wrap">
				<table class="fort-table">
					<thead><tr><th>IP Address</th><th>Label</th><th>Status</th><th>Added</th></tr></thead>
					<tbody>
					<?php foreach ( $whitelist as $w ) : ?>
						<tr>
							<td><strong><?php echo esc_html( $w->ip_address ); ?></strong>
								<?php if ( $w->ip_address === $current_ip ) : ?><span class="fort-badge green" style="font-size:10px">YOU</span><?php endif; ?></td>
							<td><?php echo esc_html( $w->label ?: '—' ); ?></td>
							<td><?php echo $w->is_active ? '<span class="fort-badge green">Active</span>' : '<span class="fort-badge gray">Disabled</span>'; ?></td>
							<td class="fort-time"><?php echo esc_html( date( 'M j, Y', strtotime( $w->added_at ) ) ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>

</div><!-- /.fortress-wrap -->

<script>
(function(){
	// "My IP" button → fill blacklist IP field
	var blBtn = document.getElementById('btn-bl-my-ip');
	if ( blBtn ) {
		blBtn.addEventListener('click', function(){
			var ipField = this.closest('form').querySelector('input[name="ip_address"]');
			if ( ipField ) ipField.value = this.dataset.ip;
		});
	}
	// "Add Mine" button → fill username field
	var uwBtn = document.getElementById('btn-wl-my-username');
	if ( uwBtn ) {
		uwBtn.addEventListener('click', function(){
			var uField = this.closest('form').querySelector('input[name="username"]');
			if ( uField ) uField.value = this.dataset.username;
		});
	}
})();
</script>
