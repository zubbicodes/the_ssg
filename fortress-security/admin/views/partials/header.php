<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="fort-header">
	<div class="fort-header-brand">
		<span class="fort-shield-icon">🛡️</span>
		<div>
			<h1 class="fort-header-title">The SSG</h1>
			<p class="fort-header-sub">Advanced Protection for WordPress</p>
		</div>
	</div>
	<nav class="fort-nav">
		<a href="<?php echo admin_url( 'admin.php?page=fortress-security' ); ?>"    class="fort-nav-link <?php echo ( $GLOBALS['pagenow'] === 'admin.php' && ( $_GET['page'] ?? '' ) === 'fortress-security'    ) ? 'active' : ''; ?>">Dashboard</a>
		<a href="<?php echo admin_url( 'admin.php?page=fortress-logs' ); ?>"         class="fort-nav-link <?php echo ( isset( $_GET['page'] ) && $_GET['page'] === 'fortress-logs'        ) ? 'active' : ''; ?>">Traffic Logs</a>
		<a href="<?php echo admin_url( 'admin.php?page=fortress-scanner' ); ?>"      class="fort-nav-link <?php echo ( isset( $_GET['page'] ) && $_GET['page'] === 'fortress-scanner'      ) ? 'active' : ''; ?>">Security Scan</a>
		<a href="<?php echo admin_url( 'admin.php?page=fortress-ip-manager' ); ?>"   class="fort-nav-link <?php echo ( isset( $_GET['page'] ) && $_GET['page'] === 'fortress-ip-manager'   ) ? 'active' : ''; ?>">IP Manager</a>
		<a href="<?php echo admin_url( 'admin.php?page=fortress-settings' ); ?>"     class="fort-nav-link <?php echo ( isset( $_GET['page'] ) && $_GET['page'] === 'fortress-settings'     ) ? 'active' : ''; ?>">Settings</a>
	</nav>
</div>
