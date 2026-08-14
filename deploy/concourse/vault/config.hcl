# Vault for Concourse credential management, and for personal secrets.
#
# ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
# Concourse stores pipeline configuration verbatim, so any secret passed with
# `fly set-pipeline -l vars.yml` is readable afterwards by anyone who can run
# `fly get-pipeline`. A credential manager is the difference between a pipeline
# that *references* a secret and one that *contains* it.
#
# ── STORAGE ──────────────────────────────────────────────────────────────────
# File backend, not `-dev`. Dev mode auto-unseals and keeps everything in
# memory, which is fine for a demo and useless as a place to keep a secret you
# would be upset to regenerate. The cost is that a restart leaves Vault SEALED
# and pipelines cannot resolve credentials until someone unseals it — see
# vault-unseal.ps1. That is the honest trade for persistence on one host.
#
# ── TLS ──────────────────────────────────────────────────────────────────────
# Disabled, deliberately and with a boundary that makes it defensible: the
# listener is reachable only from the `concourse` compose network and from
# 127.0.0.1 on this host. Nothing is published to the LAN, so the plaintext
# hop is container-to-container inside one machine.
#
# This is NOT acceptable the moment Vault is reachable off-box — including
# through the Cloudflare tunnel that fronts Concourse. If that ever happens,
# terminate TLS in front of it or enable it here first.
ui = true
disable_mlock = true

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

# How Concourse addresses Vault. Service name, not IP: the credential lookup is
# performed by the Concourse WEB process, which sits on this compose network and
# resolves service names normally. The DNS caveat in docker-compose.yml applies
# to garden TASK containers, which never talk to Vault.
api_addr = "http://vault:8200"
