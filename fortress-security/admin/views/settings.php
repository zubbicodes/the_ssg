<?php
if ( ! defined( 'ABSPATH' ) ) exit;

$o = function( $key, $default = 0 ) { return get_option( $key, $default ); };
?>
<div class="fortress-wrap">
	<?php include __DIR__ . '/partials/header.php'; ?>

	<?php if ( isset( $_GET['saved'] ) ) : ?>
		<div class="fort-notice success">Settings saved successfully.</div>
	<?php endif; ?>
	<div id="discord-test-notice" class="fort-notice info" style="display:none"></div>

	<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
		<?php wp_nonce_field( 'fortress_save_settings' ); ?>
		<input type="hidden" name="action" value="fortress_save_settings">

		<!-- General -->
		<div class="fort-card">
			<div class="fort-card-header"><h3>⚙️ General</h3></div>
			<div class="fort-settings-grid">
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Fortress Enabled</strong>
						<p>Master switch. Disabling this turns off all protection.</p>
					</div>
					<label class="fort-toggle">
						<input type="checkbox" name="fortress_enabled" value="1" <?php checked( $o( 'fortress_enabled' ), 1 ); ?>>
						<span class="fort-toggle-slider"></span>
					</label>
				</div>
			</div>
		</div>

		<!-- Registration -->
		<div class="fort-card">
			<div class="fort-card-header"><h3>🔒 Registration Lockdown</h3></div>
			<div class="fort-settings-grid">
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Disable User Registration</strong>
						<p>Prevents any new user accounts from being created, including via REST API. Existing users are unaffected.</p>
					</div>
					<label class="fort-toggle">
						<input type="checkbox" name="fortress_reg_lock" value="1" <?php checked( $o( 'fortress_reg_lock' ), 1 ); ?>>
						<span class="fort-toggle-slider"></span>
					</label>
				</div>
			</div>
		</div>

		<!-- Admin IP Whitelist -->
		<div class="fort-card">
			<div class="fort-card-header"><h3>🛡️ Admin IP Whitelist</h3></div>
			<div class="fort-settings-grid">
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Enable IP Whitelist</strong>
						<p>Only whitelisted IPs can access <code>wp-admin</code> and <code>wp-login.php</code>. <strong>Make sure your IP is whitelisted first!</strong></p>
					</div>
					<label class="fort-toggle">
						<input type="checkbox" name="fortress_ip_whitelist_enabled" value="1" <?php checked( $o( 'fortress_ip_whitelist_enabled' ), 1 ); ?>>
						<span class="fort-toggle-slider"></span>
					</label>
				</div>
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Redirect Blocked Users To</strong>
						<p>URL to redirect blocked IPs to instead of showing a 403 error. Leave blank to show the default error page.</p>
					</div>
					<input type="url" name="fortress_whitelist_redirect" class="fort-input" placeholder="https://example.com" value="<?php echo esc_attr( $o( 'fortress_whitelist_redirect', '' ) ); ?>">
				</div>
			</div>
		</div>

		<!-- XML-RPC -->
		<div class="fort-card">
			<div class="fort-card-header"><h3>⚡ XML-RPC</h3></div>
			<div class="fort-settings-grid">
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Block XML-RPC</strong>
						<p>Disables the XML-RPC API entirely. Recommended unless you specifically use it for Jetpack or remote publishing.</p>
					</div>
					<label class="fort-toggle">
						<input type="checkbox" name="fortress_block_xmlrpc" value="1" <?php checked( $o( 'fortress_block_xmlrpc' ), 1 ); ?>>
						<span class="fort-toggle-slider"></span>
					</label>
				</div>
			</div>
		</div>

		<!-- Logging -->
		<div class="fort-card">
			<div class="fort-card-header"><h3>📋 Traffic Logging</h3></div>
			<div class="fort-settings-grid">
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Enable Traffic Logging</strong>
						<p>Logs all HTTP requests with threat detection analysis.</p>
					</div>
					<label class="fort-toggle">
						<input type="checkbox" name="fortress_logging_enabled" value="1" <?php checked( $o( 'fortress_logging_enabled' ), 1 ); ?>>
						<span class="fort-toggle-slider"></span>
					</label>
				</div>
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Log Retention (Days)</strong>
						<p>Logs older than this many days are automatically deleted. Recommended: 30.</p>
					</div>
					<input type="number" name="fortress_log_retention_days" class="fort-input-num" min="1" max="365" value="<?php echo (int) $o( 'fortress_log_retention_days', 30 ); ?>">
				</div>
			</div>
		</div>

		<!-- Brute Force -->
		<div class="fort-card">
			<div class="fort-card-header"><h3>🔐 Brute Force Detection</h3></div>
			<div class="fort-settings-grid">
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Alert Threshold (Failed Logins)</strong>
						<p>Send a brute-force alert after this many failed logins from the same IP.</p>
					</div>
					<input type="number" name="fortress_brute_threshold" class="fort-input-num" min="1" max="100" value="<?php echo (int) $o( 'fortress_brute_threshold', 5 ); ?>">
				</div>
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Detection Window (Minutes)</strong>
						<p>Count failed logins within this many minutes when detecting brute force.</p>
					</div>
					<input type="number" name="fortress_brute_window" class="fort-input-num" min="1" max="1440" value="<?php echo (int) $o( 'fortress_brute_window', 10 ); ?>">
				</div>
			</div>
		</div>

		<!-- Discord -->
		<div class="fort-card">
			<div class="fort-card-header">
				<h3>🔔 Discord Notifications</h3>
				<button type="button" id="btn-test-discord" class="fort-btn blue-outline">Send Test</button>
			</div>
			<div class="fort-settings-grid">
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Enable Discord Alerts</strong>
						<p>Send notifications to Discord when security events occur.</p>
					</div>
					<label class="fort-toggle">
						<input type="checkbox" name="fortress_discord_enabled" value="1" <?php checked( $o( 'fortress_discord_enabled' ), 1 ); ?>>
						<span class="fort-toggle-slider"></span>
					</label>
				</div>
				<div class="fort-setting-row">
					<div class="fort-setting-info">
						<strong>Webhook URL</strong>
						<p>Discord channel webhook URL. Create one via Server Settings → Integrations → Webhooks.</p>
					</div>
					<input type="url" name="fortress_discord_webhook" class="fort-input" placeholder="https://discord.com/api/webhooks/..." value="<?php echo esc_attr( $o( 'fortress_discord_webhook', '' ) ); ?>">
				</div>

				<div class="fort-setting-section-title">Alert Triggers</div>

				<div class="fort-setting-row compact">
					<div class="fort-setting-info"><strong>Blocked Access</strong><p>When a request is blocked (IP whitelist, xmlrpc, etc.)</p></div>
					<label class="fort-toggle"><input type="checkbox" name="fortress_discord_on_block"      value="1" <?php checked( $o( 'fortress_discord_on_block' ),      1 ); ?>><span class="fort-toggle-slider"></span></label>
				</div>
				<div class="fort-setting-row compact">
					<div class="fort-setting-info"><strong>Failed Login</strong><p>Every failed login attempt</p></div>
					<label class="fort-toggle"><input type="checkbox" name="fortress_discord_on_login_fail" value="1" <?php checked( $o( 'fortress_discord_on_login_fail' ), 1 ); ?>><span class="fort-toggle-slider"></span></label>
				</div>
				<div class="fort-setting-row compact">
					<div class="fort-setting-info"><strong>Brute Force</strong><p>When threshold of failed logins is reached</p></div>
					<label class="fort-toggle"><input type="checkbox" name="fortress_discord_on_brute"      value="1" <?php checked( $o( 'fortress_discord_on_brute' ),      1 ); ?>><span class="fort-toggle-slider"></span></label>
				</div>
				<div class="fort-setting-row compact">
					<div class="fort-setting-info"><strong>Scanner / Probe</strong><p>When a known scanner or attack tool is detected</p></div>
					<label class="fort-toggle"><input type="checkbox" name="fortress_discord_on_scan"       value="1" <?php checked( $o( 'fortress_discord_on_scan' ),       1 ); ?>><span class="fort-toggle-slider"></span></label>
				</div>
			</div>
		</div>

		<div style="padding: 8px 0">
			<button type="submit" class="fort-btn blue fort-btn-lg">Save Settings</button>
		</div>

	</form>
</div>
