// CloudCanary — scheduled drift-detection pipeline
//
// Runs the canary sweep every 30 minutes. The Slack webhook is injected
// from the Jenkins credential store (Secret Text), never committed.
// GCP auth comes from the agent's service account (Workload Identity /
// attached SA preferred; activated key file acceptable for lab use).

pipeline {
    agent { label 'gcp-tools' }   // agent with gcloud + jq installed

    triggers {
        cron('H/30 * * * *')      // every 30 minutes, hash-balanced
    }

    options {
        disableConcurrentBuilds() // state files are not concurrency-safe
        timeout(time: 20, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '100'))
    }

    environment {
        SLACK_WEBHOOK_URL = credentials('cloudcanary-slack-webhook')
        STATE_DIR         = "${JENKINS_HOME}/cloudcanary-state"
        // PROJECT_INCLUDE_FILTER = "parent.id=123456789"   // optionally scope to a folder/org
        // PROJECT_EXCLUDE_REGEX  = "^(sandbox-|scratch-)"  // optionally skip noisy projects
    }

    stages {
        stage('Preflight') {
            steps {
                sh '''
                  gcloud auth list --filter=status:ACTIVE --format='value(account)'
                  command -v jq >/dev/null
                '''
            }
        }
        stage('Canary sweep') {
            steps {
                sh 'chmod +x cloudcanary.sh && ./cloudcanary.sh'
            }
        }
    }

    post {
        failure {
            // Operational alert: the canary itself failing is a detection gap.
            sh '''
              jq -n --arg text ":warning: CloudCanary pipeline FAILED on ${JOB_NAME} #${BUILD_NUMBER} — detection gap until next successful run." '{text: $text}' \
                | curl -fsS -X POST -H 'Content-type: application/json' --data @- "$SLACK_WEBHOOK_URL" || true
            '''
        }
    }
}
