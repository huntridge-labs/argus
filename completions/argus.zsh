#compdef argus

# Zsh completion for argus CLI
# Source this file or copy to a directory in $fpath:
#   source completions/argus.zsh

_argus() {
    local -a commands scanners severity formats

    commands=(
        'init:Initialize argus.yml for the current project'
        'scan:Run security scanners against a target'
        'collect:Collect and merge results from parallel CI jobs'
        'report:Generate reports from existing scan results'
        'validate:Validate an argus.yml configuration file'
    )

    scanners=(
        bandit checkov clamav container gitleaks
        lint-dockerfile lint-javascript lint-json
        lint-python lint-terraform lint-yaml
        opengrep osv supply-chain trivy-iac zap
    )

    severity=(critical high medium low none)
    formats=(terminal markdown sarif json)

    _arguments -C \
        '--version[Show version]' \
        '--help[Show help]' \
        '1:command:->command' \
        '*::arg:->args'

    case "$state" in
        command)
            _describe 'command' commands
            ;;
        args)
            case "${words[1]}" in
                scan)
                    _arguments \
                        '1:scanner:($scanners)' \
                        '(-p --path)'{-p,--path}'[Path to scan]:path:_files -/' \
                        '(-c --config)'{-c,--config}'[Path to argus.yml]:config:_files' \
                        '(-o --output-dir)'{-o,--output-dir}'[Output directory]:dir:_files -/' \
                        '(-s --severity-threshold)'{-s,--severity-threshold}'[Fail threshold]:severity:($severity)' \
                        '(-f --format)'{-f,--format}'[Output format]:format:($formats)' \
                        '--output-vars[Write counts to file]:file:_files' \
                        '--list[List available scanners]' \
                        '(-v --verbose)'{-v,--verbose}'[Enable verbose output]' \
                        '--no-spinner[Disable spinner]' \
                        '--no-timestamp[Flat output directory]' \
                        '--fail-fast[Abort on first failure]' \
                        '--timeout[Per-scanner timeout]:seconds:' \
                        '--image[Container image to scan]:image:' \
                        '--discover[Discover Dockerfiles]:path:_files -/' \
                        '--scanners[Sub-scanners for container]:scanners:' \
                        '--target[URL to scan]:url:' \
                        '--port[Override exposed port]:port:' \
                        '--env[Environment variable]:env:' \
                        '--scan-type[ZAP scan type]:type:(baseline full)' \
                        '--startup-timeout[Target startup timeout]:seconds:'
                    ;;
                report)
                    _arguments \
                        '1:format:($formats)' \
                        '(-r --results-dir)'{-r,--results-dir}'[Results directory]:dir:_files -/' \
                        '(-o --output-dir)'{-o,--output-dir}'[Output directory]:dir:_files -/' \
                        '(-v --verbose)'{-v,--verbose}'[Enable verbose output]'
                    ;;
                validate)
                    _arguments \
                        '(-c --config)'{-c,--config}'[Path to argus.yml]:config:_files' \
                        '--check-tools[Check scanner availability]' \
                        '--strict[Treat warnings as errors]'
                    ;;
                init)
                    _arguments \
                        '--platform[Generate CI workflow]:platform:(github gitlab jenkins none)' \
                        '--force[Overwrite existing config]' \
                        '--no-detect[Skip auto-detection]'
                    ;;
                collect)
                    _arguments \
                        '1:input directory:_files -/' \
                        '(-o --output-dir)'{-o,--output-dir}'[Output directory]:dir:_files -/' \
                        '(-v --verbose)'{-v,--verbose}'[Enable verbose output]'
                    ;;
            esac
            ;;
    esac
}

# Register when sourced directly (not via fpath)
compdef _argus argus 2>/dev/null
