// Argus Security Scan — Jenkins Pipeline
//
// Runs argus scan, archives results, and posts PR comments.
//
// Prerequisites:
//   - argus.yml in the repository root (run: argus init)
//   - Python 3.11+ installed on the agent
//   - Docker available on the agent
//   - Pipeline Utility Steps plugin (for readFile)
//
// Add this as a Jenkinsfile or include in your existing pipeline.

pipeline {
    agent any

    environment {
        ARGUS_RESULTS = 'argus-results'
    }

    stages {
        stage('Setup') {
            steps {
                checkout scm
                sh 'pip install pyyaml'  // Will become: pip install argus-security
            }
        }

        stage('Security Scan') {
            steps {
                sh """
                    python -m argus scan \
                        --format sarif --format json --format markdown \
                        --output-dir ./${ARGUS_RESULTS} \
                        --output-vars ./${ARGUS_RESULTS}/counts.env \
                        --no-timestamp \
                        || true
                """

                // Load scan counts as environment variables
                script {
                    if (fileExists("${ARGUS_RESULTS}/counts.env")) {
                        def counts = readFile("${ARGUS_RESULTS}/counts.env")
                        counts.split('\n').each { line ->
                            def parts = line.split('=', 2)
                            if (parts.length == 2) {
                                env[parts[0].trim()] = parts[1].trim()
                            }
                        }
                    }
                }

                echo "Findings — Critical:${env.critical_count ?: 0} High:${env.high_count ?: 0} Medium:${env.medium_count ?: 0} Low:${env.low_count ?: 0}"
            }
        }

        stage('Report') {
            steps {
                // Archive scan artifacts
                archiveArtifacts artifacts: "${ARGUS_RESULTS}/**", allowEmptyArchive: true

                // Publish SARIF (requires Warnings NG plugin)
                recordIssues(
                    tools: [sarif(pattern: "${ARGUS_RESULTS}/argus-results.sarif")],
                    qualityGates: [[threshold: 1, type: 'TOTAL_HIGH', unstable: true]]
                )
            }
        }

        // Optional: post PR comment (requires GitHub/Bitbucket plugin)
        // stage('PR Comment') {
        //     when { changeRequest() }
        //     steps {
        //         script {
        //             def summary = readFile("${ARGUS_RESULTS}/argus-summary.md")
        //             def comment = "## 🔒 Argus Security Scan Results\n\n${summary}"
        //             // GitHub: use GitHub PR Comment plugin
        //             // Bitbucket: use HTTP Request plugin with Bitbucket API
        //             pullRequest.comment(comment)
        //         }
        //     }
        // }
    }

    post {
        always {
            // Fail build if findings exceed threshold
            script {
                if (env.passed == 'false') {
                    unstable('Security findings exceed severity threshold')
                }
            }
        }
    }
}
