#compdef argus

# Zsh completion for argus CLI
# Copy to a directory in your $fpath, or source directly:
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

    if (( CURRENT == 2 )); then
        _describe 'command' commands
        return
    fi

    case "${words[2]}" in
        scan)
            if (( CURRENT == 3 )) && [[ "${words[3]}" != -* ]]; then
                _describe 'scanner' scanners
                return
            fi
            _arguments \
                '--path[Path to scan]:path:_files -/' \
                '--config[Path to argus.yml]:config:_files' \
                '--output-dir[Output directory]:dir:_files -/' \
                '--severity-threshold[Fail threshold]:severity:($severity)' \
                '--format[Output format]:format:($formats)' \
                '--output-vars[Write counts to file]:file:_files' \
                '--list[List available scanners]' \
                '--verbose[Enable verbose output]' \
                '--no-spinner[Disable spinner]' \
                '--no-timestamp[Flat output directory]' \
                '--fail-fast[Abort on first failure]' \
                '--timeout[Per-scanner timeout]:seconds:' \
                '--image[Container image to scan]:image:' \
                '--discover[Discover Dockerfiles]:path:_files -/' \
                '--target[URL to scan]:url:' \
                '--scan-type[ZAP scan type]:type:(baseline full)'
            ;;
        report)
            if (( CURRENT == 3 )); then
                _describe 'format' formats
                return
            fi
            _arguments \
                '--results-dir[Results directory]:dir:_files -/' \
                '--output-dir[Output directory]:dir:_files -/' \
                '--verbose[Enable verbose output]'
            ;;
        validate)
            _arguments \
                '--config[Path to argus.yml]:config:_files' \
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
                '--output-dir[Output directory]:dir:_files -/' \
                '--verbose[Enable verbose output]'
            ;;
    esac
}

_argus "$@"
