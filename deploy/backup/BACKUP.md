# Backup and restore

Added 2026-10-18 (TheHub #60842). Before this, Mykronos had no backup of
anything: the operational database, the lake, MinIO and Vault's storage each
lived in exactly one Docker volume on one host.

The approach is TheHub's (`TheHub-main/docs/runbooks/backup-and-restore.md`):
create at 03:00, verify at 04:00, encrypt with TheHub's `HUBENC1` format, copy
to the same Azure storage account in a container of its own, and prove the
backup by restoring it, not by looking at it.

## The chain

| Stage | What | When |
|---|---|---|
| Create | `deploy/backup/Backup-MyKronos.ps1`, task "Mykronos Backup (create)" | 03:00 daily |
| Verify | `deploy/backup/Test-MyKronosRestore.ps1`, task "Mykronos Backup (verify)" | 04:00 daily |
| Offsite | same run as create; block blobs under `mykronos-backups/<set>/` | per backup |
| Local prune | same run as create, only after a fully good run | per backup |
| Offsite expiry | an Azure lifecycle rule on the container (the SAS cannot delete) | Azure |

A set is `<backup root>\mykronos_<yyyyMMdd>_<HHmmss>\` holding one encrypted
file per component and a plaintext `manifest.json`. The default backup root is
`%USERPROFILE%\Backups\mykronos`; logs are in its `logs\`.

## What is backed up

| Component | Source | How |
|---|---|---|
| `operational-db` | `/data/mykronos.db` in `mykronos-backend` (SQLite, WAL) | SQLite's online backup API, run **inside the running backend** with `docker exec`, then `integrity_check` and per-table row counts. Never a file copy: a copy of a WAL database taken mid-write is a torn database. |
| `datalake` | volume `mykronos_mykronos-data`, `/datalake` | `tar.gz` through a throwaway container, volume mounted **read-only**, `--network none`. `_buffer` is archived first and `*.tmp` is skipped (below). |
| `minio` | volume `mykronos-concourse_minio-data` | same, whole volume |
| `vault-storage` | volume `mykronos-concourse_vault-data` (`/vault/file`) | same. This is Vault's storage, which Vault itself keeps encrypted. |

The live database is `sqlite:////data/mykronos.db` (checked 2026-10-18). If
`MYKRONOS_DATABASE_URL` is ever pointed at Postgres, the snapshot refuses and
the run fails, rather than quietly backing up the wrong thing.

**Consistency.** The database snapshot is transactionally consistent. The
volume tars are taken live. The lake writes each Parquet file to `.tmp` and
renames it (`lake/compaction.py`), so a tar sees whole files. Archiving the
buffer first means a compaction that runs mid-tar can duplicate buffered rows
into the archive but cannot drop them. MinIO objects written during the tar
can be torn; at 03:00 that window is normally empty. GNU tar's "file changed
as we read it" is recorded as a warning in the manifest, not a failure.

## What is not, and why

Written into every manifest under `excluded`, so the answer travels with the
backup.

| Not backed up | Why |
|---|---|
| Registry (`mykronos-concourse_registry-data`) | 83 GB measured 2026-10-18, about 20x everything else together, and every image in it is rebuilt from source by the pipelines. After a loss, a deploy that pulls a pinned digest fails until that image is rebuilt and pushed. |
| Concourse database | Pipelines are set from `deploy/concourse/pipelines` in this repo. Build history and resource versions regenerate. The secrets pipelines use are in Vault, which is backed up. |
| Concourse worker volumes, Trivy cache | Caches. |
| **Vault's unseal key and root token** | `deploy/concourse/vault/init.json`, a file in the checkout. **Never** copied by this chain: a backup holding both the sealed storage and the key that opens it protects nothing. Restoring `vault-storage` needs that key, so keep `init.json` somewhere off this host yourself (#60836). Without it, a restored Vault stays sealed for ever. |

## Encryption

Each component file is `HUBENC1`, byte-for-byte TheHub's format
(`TheHub-main/backend/services/backup_encryption.py`): Fernet frames plus a
sealed header carrying the plaintext length and SHA-256, so a truncated file is
refused rather than restored as a short prefix. `backend/tests/test_backup_scripts.py`
round-trips archives with Python's Fernet in both directions, so TheHub's
decrypt opens these archives and this one opens TheHub's.

`manifest.json` is not encrypted, as in TheHub: it lists file names, sizes and
hashes so a run's outcome can be read without the key. The data is in the
payload.

**The key.** A Fernet key (url-safe base64 of 32 bytes). Nothing in this chain
mints one. Use a key of its own rather than TheHub's, so that one key leaking
or being rotated does not touch the other estate; store it where TheHub's is
stored, which is not this host and not the Azure account the backups go to.
Losing it loses every archive written under it. After a rotation, keep the old
key until the last set written with it has expired locally and in Azure; each
manifest records `encryption.key_fingerprint` so you can tell which key a set
needs.

**It fails closed.** No key, or a malformed one, and the create task refuses
before it snapshots anything and creates no set directory.

## Exit codes and what to do

Create (`Backup-MyKronos.ps1`), last log line `--- complete, verdict <v> ---`:

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | ok | all four components captured, encrypted, hashed; offsite copy landed; old sets pruned |
| 1 | failed | a component or the upload failed, or the run refused to start. Read the log. Nothing is pruned. |
| 2 | degraded | the local set is complete but no upload SAS is configured: one copy, in the same room as its source |

Verify (`Test-MyKronosRestore.ps1`), last line `--- drill complete, verdict <v> ---`;
the per-check results are also written as `drill-<stamp>.json` in the set:

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | pass | the newest good set is under 36 h old and every component restored and checked out |
| 1 | fail | a real defect: a hash mismatch, a file that will not decrypt, a key table empty, a Parquet file DuckDB cannot read, Vault reading the storage as uninitialised, a file missing from Azure -- or no usable backup at all |
| 2 | inconclusive | the drill could not run (Docker not reachable, an image missing). Says nothing about the backup. |

What the drill checks: each file's size and SHA-256 against the manifest; each
decrypts with this host's key; the SQLite snapshot passes `integrity_check`,
its row counts equal the ones recorded at backup time, and `repo_onboardings`,
`audit_log`, `capability_configs` and `ingestion_tokens` are not empty; the
lake untars into a throwaway volume and DuckDB reads every Parquet file, with
the count matching the manifest; MinIO's `format.json` parses and its object
count matches; a throwaway Vault (`--network none`) started on the restored
storage reports `initialized: true, sealed: true` -- it is never unsealed;
and, when a read SAS is configured, every file of the set is in Azure at the
same size. Everything it creates is named `mykronos-drill-*` and removed.

## Operator setup, once

1. **Generate the key off this host** and store it where TheHub's backup key
   lives:

       python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

2. **Create the container and two SAS URLs** in TheHub's storage account
   (`thehubstorage2026`). The container is separate from `thehub-files` on
   purpose: TheHub's blob lifecycle sweep works on `thehub-files` and must
   never be pointed here. With the account key in `AZURE_STORAGE_KEY` (Azure
   portal, Storage account, Access keys; never on a command line):

       az storage container create --account-name thehubstorage2026 -n mykronos-backups
       az storage container generate-sas --account-name thehubstorage2026 -n mykronos-backups --permissions cw --expiry 2027-10-18 --https-only -o tsv
       az storage container generate-sas --account-name thehubstorage2026 -n mykronos-backups --permissions rl --expiry 2027-10-18 --https-only -o tsv

   Each SAS URL is `https://thehubstorage2026.blob.core.windows.net/mykronos-backups?<token>`.
   The upload SAS is create+write only: it cannot read, list or delete, so a
   stolen copy cannot destroy the offsite backups. The create task warns
   (in its log and the manifest) once the upload SAS is within 14 days of
   expiry.

3. **Expiry in Azure.** Portal, Storage account, Lifecycle management, add a
   rule: blob prefix `mykronos-backups/`, delete base blobs older than 90
   days (or what you choose). The scripts never delete from Azure.

4. **Store the secrets for your Windows user** (masked prompts; DPAPI, so only
   you on this machine can read them back):

       pwsh -File deploy\backup\Register-MyKronosBackupTasks.ps1 -SetSecrets

5. **Dry runs** -- print the plan and the preflight, write nothing:

       pwsh -File deploy\backup\Backup-MyKronos.ps1 -DryRun
       pwsh -File deploy\backup\Test-MyKronosRestore.ps1 -DryRun

6. **First real run, then the drill, by hand:**

       pwsh -File deploy\backup\Backup-MyKronos.ps1        # expect verdict ok, exit 0
       pwsh -File deploy\backup\Test-MyKronosRestore.ps1   # expect verdict pass
       pwsh -File deploy\backup\Test-MyKronosRestore.ps1 -Source Azure

   The `-Source Azure` drill pulls the set back down and restores it: until
   that has passed once, the offsite copy is a hypothesis.

7. **Register the two tasks** (prompts for your Windows password: the tasks
   run with LogonType Password, because an S4U task cannot read DPAPI secrets):

       pwsh -File deploy\backup\Register-MyKronosBackupTasks.ps1 -WhatIf
       pwsh -File deploy\backup\Register-MyKronosBackupTasks.ps1

   Docker Desktop must be running for your user at 03:00 and 04:00; when it is
   not, create exits 1 and the drill exits 2, both saying so.

## Restoring for real

Stop the stack first; restoring writes the live volumes, which no scheduled
script ever does.

    # 1. Get the set (local, or from Azure into an empty folder) and decrypt each file
    Import-Module .\deploy\backup\MyKronosBackup.psm1
    $key = Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText
    Get-ChildItem <set>\*.hubenc | ForEach-Object {
      Unprotect-BackupFile -Path $_.FullName -Destination ($_.FullName -replace '\.hubenc$','') -Key $key
    }

    # 2. With the stack down, load each volume (example: the lake)
    docker run --rm -v mykronos_mykronos-data:/dst -v <set>:/src:ro mykronos-backend:latest sh -c "rm -rf /dst/datalake && mkdir /dst/datalake && tar -xzf /src/datalake.tar.gz -C /dst/datalake && chown -R 10001:10001 /dst/datalake"

The database goes back as a file: copy `operational-db.sqlite` to
`/data/mykronos.db` in the same volume, removing any `mykronos.db-wal` and
`mykronos.db-shm` beside it, owned by uid 10001. MinIO and Vault each restore
by untarring into their emptied volume. Vault then comes up sealed; unseal it
with `deploy/concourse/vault-unseal.ps1` and the `init.json` you kept.

`Unprotect-BackupFile` refuses a truncated file or a wrong key and leaves no
output, so a bad archive can never half-load a volume.
