#!/usr/bin/with-contenv bashio
# ==============================================================================
# Access Control add-on entrypoint
# ==============================================================================
set -e

# Default config values. Overridden below based on environment.
LOG_LEVEL=info
USE_SUPERVISOR=true
# Internal container port — kept in sync with config.yaml's `ports` key
# and the `webui` / `watchdog` URL fragments.
PORT=8080

# Pick a config source:
#   1. Supervisor reachable → use bashio::config (the canonical path; honors
#      live schema validation). A bashio failure here surfaces via `set -e`,
#      which is what we want — a malformed options.json or schema mismatch
#      should crash the add-on with a clear error rather than silently fall
#      back to defaults.
#   2. /data/options.json present but Supervisor unreachable → parse directly
#      with jq (this is the local-docker-test path). Keys missing from the
#      file fall through to the defaults above.
#   3. Neither → log a warning and use defaults.
if bashio::supervisor.ping >/dev/null 2>&1; then
    LOG_LEVEL=$(bashio::config 'log_level')
    USE_SUPERVISOR=$(bashio::config 'use_supervisor_api')
elif [ -f /data/options.json ]; then
    bashio::log.warning \
        "Supervisor API unreachable; reading /data/options.json directly"
    LOG_LEVEL=$(jq -r '.log_level // "info"' /data/options.json)
    USE_SUPERVISOR=$(jq -r '.use_supervisor_api // true' /data/options.json)
else
    bashio::log.warning \
        "No Supervisor and no /data/options.json — using defaults \
(log_level=${LOG_LEVEL}, use_supervisor_api=${USE_SUPERVISOR})"
fi

# Defensive: an empty string from either source must not silently become an
# invalid uvicorn flag. Defaults already cover the common case; this is a
# belt-and-braces line for the (rare) case where bashio returns "" instead
# of erroring.
: "${LOG_LEVEL:=info}"
: "${USE_SUPERVISOR:=true}"

# Persistence: /data is the add-on's persistent volume (survives updates).
export DATA_DIR=/data

# RESTART_COMMAND is exec'd with shlex.split() when the user clicks the
# "Restart Service" button in the app's Settings page. In a container we
# want that path to be a no-op; the Supervisor's watchdog and "Restart"
# button on the add-on page own real restarts.
export RESTART_COMMAND="/bin/true"

# Auto-configure HA URL + token from Supervisor when requested. The app's
# main.py honors ACCESS_CONTROL_HA_URL and ACCESS_CONTROL_HA_TOKEN env-var
# overrides on every startup.
if [ "${USE_SUPERVISOR}" = "true" ]; then
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
    --forwarded-allow-ips='127.0.0.1,172.30.32.2'
# `--forwarded-allow-ips` lists IPs we trust to set X-Forwarded-For. Under
# HA Ingress the only upstream is Supervisor's proxy on the hassio Docker
# bridge (typically 172.30.32.2 / 172.30.32.0/23). We trust 127.0.0.1 too
# for local docker testing. Trusting '*' would let an attacker rotate XFF
# per request to evade rate limits — see Audit 2026-05-24, M2.
