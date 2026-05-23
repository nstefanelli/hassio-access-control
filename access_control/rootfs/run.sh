#!/usr/bin/with-contenv bashio
# ==============================================================================
# Access Control add-on entrypoint
# ==============================================================================
set -e

# bashio::config returns empty when /data/options.json is missing (e.g. in
# local docker runs outside of Supervisor). Fall back to sensible defaults.
PORT=$(bashio::config 'port' 2>/dev/null || true)
LOG_LEVEL=$(bashio::config 'log_level' 2>/dev/null || true)
USE_SUPERVISOR_RAW=$(bashio::config 'use_supervisor_api' 2>/dev/null || true)
: "${PORT:=8080}"
: "${LOG_LEVEL:=info}"
: "${USE_SUPERVISOR_RAW:=true}"

# Persistence: /data is the add-on's persistent volume (survives updates).
export DATA_DIR=/data

# RESTART_COMMAND is exec'd with shlex.split() when the user clicks the
# "Restart Service" button in the app's Settings page. In a container we
# want the process to exit; the Supervisor watchdog will then restart it.
# `/bin/true` is a no-shell-injection, always-success exec; the app's
# scheduled-reboot path will set last_reboot_fire_date and then this
# command returns, after which the watchdog probe (/health/live) keeps
# the addon alive normally. Manual restart from the app UI: users should
# instead restart the addon from the Supervisor UI.
export RESTART_COMMAND="/bin/true"

# Auto-configure HA URL + token from Supervisor when requested. The app's
# main.py already honors ACCESS_CONTROL_HA_URL and ACCESS_CONTROL_HA_TOKEN
# env-var overrides on every startup.
if [ "${USE_SUPERVISOR_RAW}" = "true" ]; then
    if [ -n "${SUPERVISOR_TOKEN:-}" ]; then
        export ACCESS_CONTROL_HA_URL="http://supervisor/core"
        export ACCESS_CONTROL_HA_TOKEN="${SUPERVISOR_TOKEN}"
        bashio::log.info "Using Supervisor proxy for Home Assistant API"
    else
        bashio::log.warning \
            "use_supervisor_api is true but SUPERVISOR_TOKEN is empty; \
falling back to user-entered HA credentials"
    fi
fi

bashio::log.info "Starting Access Control on port ${PORT} (log level: ${LOG_LEVEL})"

# `--app-dir /opt` so uvicorn imports `access_control` as a package
# (matches the existing VM setup which runs from /opt as the working dir).
exec python3 -m uvicorn access_control.main:app \
    --app-dir /opt \
    --host 0.0.0.0 \
    --port "${PORT}" \
    --log-level "${LOG_LEVEL}" \
    --no-server-header \
    --proxy-headers \
    --forwarded-allow-ips='*'
