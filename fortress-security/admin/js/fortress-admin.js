/* Fortress Security — Admin JS */
(function ($) {
	'use strict';

	/* ── Use My IP button ─────────────────────────────────────────────── */
	$('#btn-use-my-ip').on('click', function () {
		var ip = $(this).data('ip');
		$('input[name="ip_address"]').val(ip);
		if (!$('input[name="label"]').val()) {
			$('input[name="label"]').val('My IP');
		}
	});

	/* ── Auto-refresh stats on dashboard ─────────────────────────────── */
	if ($('#stat-total').length) {
		var refreshStats = function () {
			$.post(FortressAdmin.ajaxurl, {
				action : 'fortress_stats',
				nonce  : FortressAdmin.nonce
			}, function (resp) {
				if (resp.success) {
					var d = resp.data;
					$('#stat-total').text(d.total_today.toLocaleString());
					$('#stat-sus').text(d.suspicious_today.toLocaleString());
					$('#stat-blocked').text(d.blocked_today.toLocaleString());
				}
			});
		};
		// Refresh every 30 seconds
		setInterval(refreshStats, 30000);
	}

	/* ── Confirm destructive actions ──────────────────────────────────── */
	$(document).on('submit', 'form[data-confirm]', function (e) {
		var msg = $(this).data('confirm');
		if (!window.confirm(msg)) {
			e.preventDefault();
		}
	});

	/* ── Highlight current IP row in whitelist ────────────────────────── */
	$('.fort-badge:contains("YOU")').closest('tr').css('background', '#f0fdf4');

	/* ── Copy bypass URL ──────────────────────────────────────────────── */
	$('#btn-copy-bypass').on('click', function () {
		var input = document.getElementById('bypass-url');
		input.select();
		input.setSelectionRange(0, 99999);
		try {
			document.execCommand('copy');
		} catch(e) {
			navigator.clipboard && navigator.clipboard.writeText(input.value);
		}
		var btn = $(this);
		btn.text('Copied!');
		setTimeout(function () { btn.text('Copy'); }, 2500);
	});

	/* ── Logs: expand URI on click ────────────────────────────────────── */
	$(document).on('click', '.fort-uri', function () {
		var $td = $(this);
		if ($td.hasClass('expanded')) {
			$td.removeClass('expanded').css({
				'max-width': '220px',
				'white-space': 'nowrap',
				'overflow': 'hidden',
			});
		} else {
			$td.addClass('expanded').css({
				'max-width': 'none',
				'white-space': 'normal',
				'overflow': 'visible',
			});
		}
	});

	/* ── Discord test button (AJAX — avoids nested form problem) ─────── */
	$('#btn-test-discord').on('click', function () {
		var btn = $(this);
		btn.prop('disabled', true).text('Sending…');
		$.post(FortressAdmin.ajaxurl, {
			action : 'fortress_test_discord',
			nonce  : FortressAdmin.nonce
		}, function (resp) {
			var msg = resp.success ? resp.data : (resp.data || 'Error sending test.');
			$('#discord-test-notice').text(msg).show();
			btn.prop('disabled', false).text('Send Test');
			setTimeout(function () { $('#discord-test-notice').fadeOut(); }, 6000);
		}).fail(function () {
			$('#discord-test-notice').text('Request failed. Check your webhook URL and save settings first.').show();
			btn.prop('disabled', false).text('Send Test');
		});
	});

	/* ── Security Scanner ────────────────────────────────────────────── */
	$('#btn-run-scan').on('click', function () {
		var scope = $('input[name="scan_scope"]:checked').val() || 'full';
		$('#scan-progress').show();
		$('#btn-run-scan').prop('disabled', true);
		$('#scan-btn-text').text('Scanning…');

		$.post(FortressAdmin.ajaxurl, {
			action : 'fortress_run_scan',
			nonce  : FortressAdmin.nonce,
			scope  : scope
		}, function () {
			// Reload to show fresh results
			window.location.reload();
		}).fail(function () {
			$('#scan-progress').hide();
			$('#btn-run-scan').prop('disabled', false);
			$('#scan-btn-text').text('▶ Run Scan');
			alert('Scan failed. The server may have timed out on a large site. Try "Quick" scope.');
		});
	});

	/* ── Dismiss finding ──────────────────────────────────────────────── */
	$(document).on('click', '.btn-dismiss-finding', function () {
		var id  = $(this).data('id');
		var row = $(this).closest('.fort-finding');
		$.post(FortressAdmin.ajaxurl, {
			action         : 'fortress_dismiss_finding',
			nonce          : FortressAdmin.nonce,
			finding_id     : id,
			dismiss_action : 'dismiss'
		}, function () {
			row.fadeOut(300);
		});
	});

	/* ── Restore dismissed finding ────────────────────────────────────── */
	$(document).on('click', '.btn-undismiss-finding', function () {
		var id  = $(this).data('id');
		var row = $(this).closest('.fort-finding');
		$.post(FortressAdmin.ajaxurl, {
			action         : 'fortress_dismiss_finding',
			nonce          : FortressAdmin.nonce,
			finding_id     : id,
			dismiss_action : 'restore'
		}, function () {
			row.fadeOut(300, function () { window.location.reload(); });
		});
	});

	/* ── Filter findings ──────────────────────────────────────────────── */
	$(document).on('click', '[data-filter]', function () {
		var sev = $(this).data('filter');
		$('#findings-list .fort-finding').each(function () {
			var show = !sev || $(this).data('severity') === sev;
			$(this).toggle(show);
		});
	});

	$(document).on('click', '[data-filter-type]', function () {
		var type = $(this).data('filter-type');
		$('#findings-list .fort-finding').each(function () {
			$(this).toggle($(this).data('type') === type);
		});
	});

	/* ── Fade notices ─────────────────────────────────────────────────── */
	setTimeout(function () {
		$('.fort-notice.success').fadeOut(800);
	}, 8000);

})(jQuery);
