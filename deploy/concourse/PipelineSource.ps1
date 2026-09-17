<#
.SYNOPSIS
    One source-of-truth guard for every `fly set-pipeline` in this directory.

.DESCRIPTION
    Dot-source this. It gives the three set-*-pipeline.ps1 scripts a single
    answer to "which version of the configuration is this apply about to
    push", and there is no second answer for a sibling to drift from.

    B-59073 established the rule on set-thehub-pipeline.ps1: the pipeline
    source is `main`, and only `main`. That script read pipelines\thehub.yml
    off disk, so the live pipeline - the control every TheHub production
    deploy passes through - was whatever the checkout happened to hold at the
    moment somebody ran it. It failed twice, in opposite directions:

      2026-09-08  the checkout sat 129 commits BEHIND its branch. Three
                  applies pushed a stale template. A phantom "orphaned
                  dast-staging" job, persistent drift warnings and a
                  sast/semgrep naming mismatch were then chased as real bugs;
                  the mismatch was "fixed" redundantly. All three were
                  artifacts of the stale apply.
      2026-09-10  the checkout sat on a feature branch, 3 commits AHEAD of
                  origin/main and unmerged. An apply would have put unreviewed
                  pipeline changes in front of production.

    Behind and ahead are one defect: the source of a production control was a
    mutable working tree.

    -- WHY THIS IS A SHARED FILE, AND NOT A THIRD COPY OF THE GUARD ---------

    B-59073 hardened one of three siblings. `set-pipeline.ps1` (mykronos) and
    `set-personal-soc-pipeline.ps1` had nothing: no branch refusal, no
    clean-tree check, and both applied whatever was on disk from any branch,
    dirty. The fourth firing of the defect was a worktree 162 commits behind
    on a branch that does not define `dast-staging` - one apply away from
    deleting a security lane from the server. personal-soc is a security
    pipeline; this is not an academic exposure.

    Copying the guard into the other two would fix the instance and leave the
    shape: three scripts kept in step, which is the same drift that produced
    this story. A guard applied to one of three siblings left two behind, so
    the fix is one implementation the siblings call, not three they maintain.

    -- WHAT IS ACTUALLY LOAD-BEARING ---------------------------------------

    Not the checks. `Resolve-PipelineConfig` reads the configuration out of
    the `main` COMMIT with `git show <sha>:<path>`, never off disk. Once that
    SHA is resolved the bytes are immutable, and a branch switch mid-run
    cannot reach them. That closes the race by construction rather than by
    being quick enough, and it is the part worth copying.

    Checking the tree faster only narrows the race. B-59073 established this
    by trying the procedural version: the preconditions were verified by hand
    - HEAD on main, zero behind origin/main after a fast-forward, no tracked
    modifications - and the apply that followed announced it was applying from
    `docs/retro-2026-09-11 @ 62cfdac`. Somebody else works in that tree and
    switched branches in the seconds between the check and the apply. There is
    no interval short enough to check in.

    The refusals still matter, for two reasons. The YAML is not the only thing
    an apply is made of: the vars beneath it - the branch delivered,
    `mykronos-ref`, the environment URLs - come from the *script*, which
    PowerShell read off disk before any of this ran. Pinning the pipeline to
    `main` and leaving those floating would only move the problem. And an
    operator should hear "no" in a second rather than after a minute of
    token-minting and a fly login.

    -- THE SHAPE THAT KEEPS A SIBLING FROM SKIPPING IT ----------------------

    `Resolve-PipelineConfig` is the only way to obtain a path to hand to
    `fly set-pipeline`, and it runs the refusals itself, immediately before
    resolving the blob, from a fresh read of git with nothing cached in
    between. A caller cannot forget the guard and still have a configuration
    to apply - omitting it means having no `--config` argument at all. That is
    a stronger property than three scripts each remembering to call an
    `Assert-` function, and it is the reason the two halves are one function
    rather than two.

.NOTES
    ASCII only - see setup.ps1 for why.
#>

#: The one branch a pipeline may be applied from (operator decision
#: 2026-09-10, option A). A parameter on every function rather than a global,
#: so a caller cannot change it for the next caller by assignment.
$script:DefaultPipelineSourceRef = "main"


function Invoke-RepoGit {
    <#
    .SYNOPSIS
        Run git in the checkout, returning the answer rather than throwing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$GitArgs
    )
    # A non-zero exit is routinely the answer here ("there is no local main")
    # rather than a failure, so both of the ways PowerShell turns one into a
    # terminating error are switched off for the length of the call. Both
    # assignments are function-scoped and end with it.
    $ErrorActionPreference = "Continue"
    $PSNativeCommandUseErrorActionPreference = $false
    $out = & git -C $Root @GitArgs 2>&1
    $code = $LASTEXITCODE
    return [pscustomobject]@{
        Ok   = ($code -eq 0)
        Text = ((($out | Out-String) -replace "`r", "").Trim())
    }
}


function Get-PipelineSourceState {
    <#
    .SYNOPSIS
        Everything the refusals below are decided from, read fresh.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$SourceRef = $script:DefaultPipelineSourceRef
    )
    # Read fresh every call, with nothing kept between them. A remembered
    # answer about a working tree is the bug this exists to stop, one
    # indirection further back.
    $top = Invoke-RepoGit -Root $Root -GitArgs @("rev-parse", "--show-toplevel")
    if (-not $top.Ok) {
        throw "$Root is not inside a git checkout, so there is no way to say " +
              "which version of the pipeline configuration an apply would push."
    }

    $local = Invoke-RepoGit -Root $Root -GitArgs @("rev-parse", "--verify", "--quiet", "refs/heads/$SourceRef")
    $remote = Invoke-RepoGit -Root $Root -GitArgs @("rev-parse", "--verify", "--quiet", "refs/remotes/origin/$SourceRef")

    # $null means "cannot be answered", which is not the same as 0 and is not
    # treated as it.
    $behind = $null
    if ($local.Ok -and $remote.Ok) {
        $count = Invoke-RepoGit -Root $Root -GitArgs @("rev-list", "--count", "$SourceRef..origin/$SourceRef")
        if ($count.Ok) { $behind = [int]$count.Text }
    }

    return [pscustomobject]@{
        Branch  = (Invoke-RepoGit -Root $Root -GitArgs @("rev-parse", "--abbrev-ref", "HEAD")).Text
        Head    = (Invoke-RepoGit -Root $Root -GitArgs @("rev-parse", "--short", "HEAD")).Text
        # Tracked files only. Untracked ones are in nobody's pipeline and this
        # checkout always has a few; refusing on them would make the guard the
        # thing people route around, which is how a guard stops working.
        Dirty   = (Invoke-RepoGit -Root $Root -GitArgs @("status", "--porcelain", "--untracked-files=no")).Text
        MainSha = $(if ($local.Ok) { $local.Text } else { $null })
        Behind  = $behind
        # "deploy/concourse/" - so the blob path is right from wherever in the
        # tree the calling script has been moved to.
        Prefix  = (Invoke-RepoGit -Root $Root -GitArgs @("rev-parse", "--show-prefix")).Text
        Ref     = $SourceRef
    }
}


function Update-PipelineSourceRemote {
    <#
    .SYNOPSIS
        Refresh origin/<ref> once, at the top of a script. Warns, never refuses.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$SourceRef = $script:DefaultPipelineSourceRef
    )
    # origin/main is itself a cached answer, and a stale one has the
    # 2026-09-08 shape exactly: a checkout that looks level because the thing
    # it is level with has not moved in a while. So refresh it, once, here -
    # and here rather than inside Resolve-PipelineConfig, because the
    # evaluation immediately before the apply has to be instant. A network
    # round trip inside it would reopen the window it exists to shut.
    #
    # A fetch that fails warns rather than refuses. An unreachable origin is a
    # visible and different condition, and turning it into "you cannot deploy"
    # would push people toward -AllowPipelineFromAnyBranch for a reason that
    # has nothing to do with what that flag means. A flag reached for out of
    # habit has stopped being a decision.
    $fetch = Invoke-RepoGit -Root $Root -GitArgs @("fetch", "--quiet", "origin", $SourceRef)
    if (-not $fetch.Ok) {
        Write-Host "Could not reach origin: the behind-check compares against whatever" -ForegroundColor Yellow
        Write-Host "  this checkout last saw of origin/$SourceRef, which may be old." -ForegroundColor Yellow
    }
    return $fetch.Ok
}


function Assert-PipelineSourceIsMain {
    <#
    .SYNOPSIS
        Refuse unless HEAD is <ref>, the tree is clean, and <ref> is level with origin.

    .DESCRIPTION
        Called twice per apply: once at the top of the calling script so a
        refusal costs a second rather than a minute, and once by
        Resolve-PipelineConfig on the line before the blob is read.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Pipeline,
        [string]$SourceRef = $script:DefaultPipelineSourceRef,
        [switch]$AllowAnyBranch
    )
    $s = Get-PipelineSourceState -Root $Root -SourceRef $SourceRef

    if ($AllowAnyBranch) {
        Write-Host ""
        Write-Host "  ############################################################" -ForegroundColor Red
        Write-Host "  ##  OVERRIDE: applying '$Pipeline' from '$($s.Branch)' @ $($s.Head)," -ForegroundColor Red
        Write-Host "  ##  and NOT from '$SourceRef'." -ForegroundColor Red
        if ($s.Dirty) {
            Write-Host "  ##  Uncommitted edits to tracked files are going in with it." -ForegroundColor Red
        }
        Write-Host "  ##" -ForegroundColor Red
        Write-Host "  ##  Until somebody re-applies from '$SourceRef', the running" -ForegroundColor Red
        Write-Host "  ##  '$Pipeline' pipeline is whatever that branch says." -ForegroundColor Red
        Write-Host "  ############################################################" -ForegroundColor Red
        Write-Host ""
        return $s
    }

    $refusals = @()
    if ($s.Branch -ne $SourceRef) {
        $refusals += "HEAD is on '$($s.Branch)', at $($s.Head). Expected '$SourceRef'."
    }
    if ($s.Dirty) {
        $refusals += "Tracked files are modified, so this tree holds a pipeline that is in " +
                     "no commit:`n      " + (($s.Dirty -split "`n") -join "`n      ")
    }
    if (-not $s.MainSha) {
        $refusals += "There is no local '$SourceRef' branch to read the configuration out of."
    } elseif ($null -eq $s.Behind) {
        $refusals += "There is no origin/$SourceRef here, so whether this checkout is " +
                     "behind cannot be answered - and behind is how 2026-09-08 happened."
    } elseif ($s.Behind -gt 0) {
        $refusals += "'$SourceRef' is $($s.Behind) commit(s) behind origin/$SourceRef, so " +
                     "applying it would push a pipeline older than the one on the server." +
                     "`n      git fetch origin $SourceRef" +
                     "`n      git merge --ff-only origin/$SourceRef"
    }

    if ($refusals) {
        # Written out rather than carried in the exception, because PowerShell
        # folds a multi-line throw message into one run-on line inside its
        # error banner - and a refusal nobody can read is most of the way back
        # to a refusal nobody gets. The exception keeps the one-line version so
        # a caller still sees why it stopped.
        Write-Host ""
        Write-Host "Refusing to apply the '$Pipeline' pipeline." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Its only source is '$SourceRef' (operator decision 2026-09-10)." -ForegroundColor Red
        foreach ($r in $refusals) {
            Write-Host ""
            Write-Host "  - $r" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "  -AllowPipelineFromAnyBranch applies this tree anyway. It says so in red," -ForegroundColor DarkGray
        Write-Host "  and the server keeps that branch's pipeline until somebody re-applies" -ForegroundColor DarkGray
        Write-Host "  from '$SourceRef'." -ForegroundColor DarkGray
        Write-Host ""
        throw ("Refusing to apply '{0}': {1}" -f $Pipeline, (($refusals[0] -split "`n")[0]))
    }

    return $s
}


function Resolve-PipelineConfig {
    <#
    .SYNOPSIS
        The refusals, then the immutable bytes. The only way to get a --config path.

    .DESCRIPTION
        Returns an object with `Path` (what to hand `fly set-pipeline
        --config`), `Temp` (true when Path is a temporary file the caller must
        delete in its finally block) and `State` (the source state, for
        printing).

        Nothing between the assert below and the caller's `fly` line waits on
        anything, which is why the second evaluation lives here rather than
        only at the top of the calling script.

    .PARAMETER RelativePath
        The configuration's path from this directory, e.g. "pipelines\thehub.yml".
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Pipeline,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [string]$SourceRef = $script:DefaultPipelineSourceRef,
        [switch]$AllowAnyBranch
    )
    # Second evaluation, from a fresh read of git, and the last thing that
    # happens before the caller applies.
    $state = Assert-PipelineSourceIsMain -Root $Root -Pipeline $Pipeline `
        -SourceRef $SourceRef -AllowAnyBranch:$AllowAnyBranch

    if ($AllowAnyBranch) {
        # Applying what is on disk is the entire point of the override.
        Write-Host "=== applying from: $($state.Branch) @ $($state.Head) (working tree) ===" -ForegroundColor Red
        return [pscustomobject]@{
            Path  = (Join-Path $Root $RelativePath)
            Temp  = $false
            State = $state
        }
    }

    # Out of the commit, not off disk. `git show <sha>:<path>` names an object
    # nobody can edit, so from this line on nothing anyone does in this
    # checkout can change what is applied.
    #
    # Through Start-Process rather than captured into a variable: these files
    # are UTF-8 and PowerShell decodes native output with the console
    # codepage, which would mangle their non-ASCII bytes on any machine not
    # set to UTF-8. Redirecting the child's stdout copies bytes.
    #
    # Those bytes carry LF where the checked-out copy has CRLF
    # (core.autocrlf). YAML normalises line breaks inside scalars, so the
    # configuration Concourse ends up holding is the same either way.
    $blob = "$($state.MainSha):$($state.Prefix)$($RelativePath -replace '\\', '/')"
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) `
        ("{0}-{1}-{2}.yml" -f $Pipeline, $state.MainSha.Substring(0, 7), (Get-Random))
    $show = Start-Process -FilePath "git" -NoNewWindow -Wait -PassThru `
        -ArgumentList @("-C", $Root, "show", $blob) `
        -RedirectStandardOutput $temp
    if ($show.ExitCode -ne 0 -or -not (Test-Path $temp) -or (Get-Item $temp).Length -eq 0) {
        if (Test-Path $temp) { Remove-Item $temp -Force }
        throw "Could not read $blob out of the '$SourceRef' commit."
    }

    Write-Host "=== applying from: $SourceRef @ $($state.MainSha.Substring(0, 7)) (committed) ===" -ForegroundColor Green
    return [pscustomobject]@{
        Path  = $temp
        Temp  = $true
        State = $state
    }
}
