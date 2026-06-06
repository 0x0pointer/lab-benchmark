#!/bin/sh
# Lab start: wait for Postgres, then run VulnBank + observer via lab_entrypoint.py.
# Mirrors upstream start.sh but swaps the final exec for the observer-wrapped entrypoint.
set -eu

DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_NAME="${DB_NAME:-vulnerable_bank}"

echo "[lab] waiting for PostgreSQL at ${DB_HOST}:${DB_PORT} ..."
until pg_isready -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" >/dev/null 2>&1; do
  sleep 2
done

echo "[lab] starting VulnBank with observer (run_id=${LAB_RUN_ID:-dev} profile=${LAB_PROFILE:-raw})"
exec python lab_entrypoint.py
