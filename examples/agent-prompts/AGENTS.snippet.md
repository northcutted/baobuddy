## Secrets & Ephemeral Access (BaoBuddy)

This repository uses **BaoBuddy** for hardware-backed (Touch ID / Face ID), time-boxed OpenBao / HashiCorp Vault access.

1. **Never ask the user to paste passwords, static Vault tokens, or API keys in chat.**
2. **Check status first**: Call `baobuddy_status` (or run `bao-buddy status`) before requesting a grant.
3. **Request minimal scope**: Call `baobuddy_list_profiles` to check policy names and audit rules, then call `baobuddy_request_grant` with the smallest policy set, shortest TTL (`hours`), and a clear `why` (including a change ticket ID if required).
4. **Respect biometric approval**: Wait for the human to approve via Touch ID / Face ID (`baobuddy_wait_for_grant`); never try to bypass or work around a missing grant.
5. **Revoke immediately when finished**: Call `baobuddy_revoke_grant` (or `bao-buddy revoke`) as soon as secret-dependent commands complete.
6. **Never handle a token directly**: don't run `bao-buddy grant --on direct` or `bao-buddy personal-token`, and don't print, store, or pass tokens as arguments. Use a local grant only inside the command that needs it, using the server-scoped Keychain service printed by `bao-buddy status` (`openbao-grant.<binding>`): `VAULT_TOKEN="$(security find-generic-password -s openbao-grant.<binding> -w)" <command>` (and `openbao-grant-artifact.<binding>` for extension credentials).
