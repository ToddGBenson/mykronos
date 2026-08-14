# L0002: A credential you cannot vault is a design choice, not a constraint

**Date:** 2026-08-14 · **Class:** local, from this repository's Concourse work
**Applies to:** every outbound integration a pipeline authenticates to
**Landed as:** the `slack_alert` anchor in `deploy/concourse/pipelines/thehub.yml` and
`personal-soc.yml`, both resolving `((slack-bot-token))` from Vault at
`concourse/main/`; the newline fix in `vault-secret.ps1`

## The lesson, in one line

**Where a secret sits in a request decides whether a credential manager can ever hold
it.** A token in a header can be substituted at egress; a token in a URL path cannot — and
that is settled when you choose the integration, long before anyone writes the pipeline.

## How it arrived

The pipeline needed to post build failures to Slack. The obvious move was the incoming
webhook already sitting in TheHub's `.env`, and it was wired in and working.

The correction came from outside the code: *the webhook is used by the hub, because that is
how the hub posts Slack messages.* Reusing it would have interleaved pipeline alerts with
the messages TheHub's app sends to people. So the first reason to change was ownership —
one credential, two unrelated senders.

The second reason only appeared while looking for the first. An incoming webhook **is** its
secret:

```
https://hooks.slack.com/services/{workspace}/{app}/{24-char-secret}
                                 └──────────── the credential ────────────┘
```

There is no header. The URL is the authentication. Vault had just been stood up on this
host specifically so that pipelines *reference* credentials rather than *contain* them —
and the webhook was the one credential it could not have managed, because Concourse
substitutes a `((var))` into a field, and here the field is the endpoint being called.

`chat.postMessage` moves the secret into `Authorization: Bearer`, and the endpoint becomes
a constant. That single change is what made `((slack-bot-token))` possible.

## The rule

When choosing between two ways to authenticate to the same service, ask **where the secret
lives in the request** before comparing anything else:

```
in a header      -> a credential manager can substitute it; the config holds a reference
in the URL path  -> the config holds the secret itself, forever
in a query param -> same as the path, and it is in access logs and Referer headers too
```

The convenience ordering is usually the reverse of the safety ordering. A webhook is
faster to set up precisely because it carries its own credential.

## What this actually bought, measured

`fly get-pipeline -p personal-soc` after the change:

```
xoxb- literal present        : False
((slack-bot-token)) present  : True
channel id literal present   : False
```

That matters because Concourse stores pipeline configuration **verbatim**. Before this,
every secret passed with `--load-vars-from` was readable afterwards by anyone who could run
`fly get-pipeline` — which the set-pipeline scripts had already noticed from the other side,
discarding fly's stdout because it prints the *resolved* config with every `((var))`
substituted. Discarding the output hid the secrets from the terminal. It did not stop them
being stored.

Team scope (`concourse/main/<name>`) rather than pipeline scope, because two pipelines send
to the same channel as the same bot. One credential, one place to rotate it.

## The bug this uncovered, which is the more useful half

Writing the token to Vault the obvious way stored it wrong:

```powershell
$token | docker exec -i mykronos-vault vault kv put concourse/main/slack-bot-token value=-
```

A 57-character token came back as 59. The PowerShell pipeline terminates what it sends with
CRLF, and `value=-` reads stdin literally, so `0D 0A` was appended to the secret.

Every symptom of this points away from the cause. The value looks correct in every log. The
length is only wrong if you check it. Slack answers **401**, which reads as a bad token, a
revoked scope, a bot removed from the channel — anything except "the store added two bytes".

Two things follow, and the second is the general one:

1. **Write secrets as bytes, not as lines.** `StandardInput.Write()`, not a pipeline.
   `vault-secret.ps1` now does this and every value it has ever written is suspect.
2. **Verify the length after a write.** It costs one read, it reveals nothing sensitive, and
   it is the only cheap check that catches transport corruption of a value you deliberately
   never look at. The script now warns when stored length differs from input length.

The general form: **a secret is the one value you never print, so it is the one value whose
corruption you will not see.** Every other string in a system gets eyeballed by accident
eventually. Secrets need a deliberate check because nothing else will ever look at them.

## The check worth stealing

Of any credential in a pipeline, ask:

1. Could a credential manager hold this, or does the integration's shape prevent it?
2. If I rotate it, how many places change?
3. Has anything confirmed the stored bytes are the bytes I typed?

Question 3 is the one nobody asks, and it is the only one with a two-minute answer.

## Related

- `docs/lessons/0001-scanners-need-a-no-input-path.md` — the same shape one level down:
  a state nobody modelled (there, "nothing to scan"; here, "stored but altered") reading as
  success.
- `deploy/concourse/VAULT.md` — the mount layout and why `concourse/` is KV v1.
