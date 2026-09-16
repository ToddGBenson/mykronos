# Before a risk can be accepted

An acceptance is a decision with a premise, and the premise is the part that
expires. This is the list of things that must be true before `accepted_risk`
is the right status — and, for the items a machine can check, the list the API
enforces.

Every item says who checks it. **Gate** means `PATCH /api/dashboard/findings/{id}/status`
refuses the acceptance if it is not satisfied. **Judgement** means nobody can
check it for you and the reason field is where you show your work.

---

## 1. The finding is real — *judgement*

`accepted_risk` and `false_positive` are different verdicts and are not
interchangeable.

- **Real, and we are living with it** → `accepted_risk`.
- **Not real** → `false_positive`.

Using acceptance for something that is not a finding corrupts two things at
once: the dampening loop reads dispositions to decide which rules to quieten,
and the risk score treats an acceptance as residual risk that still exists. A
false positive filed as an acceptance is a rule that keeps shouting and a risk
number that is permanently wrong in the same gesture.

## 2. The premise is stated, in a reason code and in words — *gate*

The code says which kind of claim you are making. The words say why it is true
*here*, on this finding.

`accepted_reason_code` has always been required. **The reason text is now
required for `critical` and `high`**, rather than being accepted and recorded
as low-confidence. At those severities a bare code is not a decision anybody
can review later, and the review date exists precisely so somebody will try.

## 3. The review window is proportionate to the severity — *gate*

An acceptance is a decision to carry the risk *for a stated period*. The period
has to bear some relation to how bad the thing is:

| severity | longest acceptance | remediation target for comparison |
|---|---|---|
| critical | 30 days | 7 days |
| high | 90 days | 30 days |
| medium | 180 days | 90 days |
| low | 365 days | 180 days |

Roughly four times the remediation target: long enough to be a real decision
rather than a deferral, short enough that a critical cannot be parked until
next year. Accepting a critical for eleven months is not a decision with a
premise; it is a way of not having the conversation.

**`indefinite` is not available for `critical` or `high`.** An acceptance with
no end has no premise that can expire, which means nothing can ever bring it
back. That is a reasonable thing to do about a low-severity finding in a
component nobody will ever change. It is not a reasonable thing to do about a
critical.

## 4. The premise is not already contradicted by evidence we hold — *gate*

Only one of the four codes makes a claim a scanner can check, and that one is
checked:

**`no_vendor_fix`** asserts no patch exists. If the scan output for this
finding names a `fixed_version`, the acceptance is refused. The platform is
holding evidence that the premise is false at the moment it is being written
down, and recording it anyway would mean the register is wrong from the first
day rather than from the review date.

`sweep_acceptances` already re-opens a `no_vendor_fix` acceptance when a fix
later appears. This is the same rule applied at the front instead of six weeks
later.

The other three codes rest on things no scanner can see, and are not gated:

- **`not_exploitable_here`** — say *what* makes the vulnerable path
  unreachable. A version, a configuration, a code path that is not compiled
  in. "We do not think it is reachable" is not a premise; it is a hope.
- **`compensating_control`** — name the control, and name where it is
  configured. A control nobody can point at cannot be checked when it is
  removed.
- **`cost_exceeds_risk`** — a judgement about this estate, which is legitimate
  and is yours to make. **Not available for `critical`** — *gate*. A critical
  where the fix costs more than the risk is a conversation about the
  architecture, not a status change.

## 5. Somebody owns the review — *automatic*

The actor is recorded from the credential used, and `accepted_until` is what
puts it back on the queue. Nothing to do; recorded here because it is part of
what makes the other four items mean anything.

---

## What acceptance does not do

**It does not remove the risk from the score.** A live, qualified acceptance
still contributes, at a reduced weight — see `modifiers.accepted_risk.residual`
in the Oracle policy. Before that existed, a repository could move every
finding out of its open counts with a status change and score as though they
were gone. They are not gone. Somebody decided to carry them, which is a
different thing from not having them.

**It does not survive its own premise.** `sweep_acceptances` returns a finding
to `open` when the review date passes, or when a `no_vendor_fix` acceptance is
contradicted by a published fix.

**It does not mean the finding is closed.** An accepted finding that the
scanner stops reporting is a separate question, and currently an unresolved
one — see #407.
