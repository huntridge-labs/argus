#!/bin/bash
# Bash completion for argus CLI
# Source this file: source completions/argus.bash
# Or copy to /etc/bash_completion.d/argus

_argus_completions() {
    local cur prev commands scanners scan_flags

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="init scan collect report validate"
    scanners="bandit checkov clamav container gitleaks lint-dockerfile lint-javascript lint-json lint-python lint-terraform lint-yaml opengrep osv supply-chain trivy-iac zap"
    severity="critical high medium low none"
    formats="terminal markdown sarif json"

    # Complete subcommands
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "$commands --version --help" -- "$cur"))
        return
    fi

    local subcmd="${COMP_WORDS[1]}"

    case "$subcmd" in
        scan)
            # Complete scanner name as second arg
            if [ "$COMP_CWORD" -eq 2 ] && [[ "$cur" != -* ]]; then
                COMPREPLY=($(compgen -W "$scanners --list --help" -- "$cur"))
                return
            fi

            case "$prev" in
                --severity-threshold|-s)
                    COMPREPLY=($(compgen -W "$severity" -- "$cur"))
                    return
                    ;;
                --format|-f)
                    COMPREPLY=($(compgen -W "$formats" -- "$cur"))
                    return
                    ;;
                --path|-p|--output-dir|-o|--config|-c|--output-vars)
                    COMPREPLY=($(compgen -d -- "$cur"))
                    return
                    ;;
                --scan-type)
                    COMPREPLY=($(compgen -W "baseline full" -- "$cur"))
                    return
                    ;;
            esac

            scan_flags="--path --config --output-dir --severity-threshold --format --list --verbose --no-spinner --no-timestamp --output-vars --fail-fast --timeout"
            COMPREPLY=($(compgen -W "$scan_flags" -- "$cur"))
            ;;
        report)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=($(compgen -W "$formats" -- "$cur"))
                return
            fi
            COMPREPLY=($(compgen -W "--results-dir --output-dir --verbose" -- "$cur"))
            ;;
        validate)
            COMPREPLY=($(compgen -W "--config --check-tools --strict" -- "$cur"))
            ;;
        init)
            case "$prev" in
                --platform)
                    COMPREPLY=($(compgen -W "github gitlab jenkins none" -- "$cur"))
                    return
                    ;;
            esac
            COMPREPLY=($(compgen -W "--platform --force --no-detect" -- "$cur"))
            ;;
        collect)
            COMPREPLY=($(compgen -W "--output-dir --verbose" -- "$cur"))
            ;;
    esac
}

complete -F _argus_completions argus
# Also complete for 'python -m argus'
complete -F _argus_completions python\ -m\ argus
