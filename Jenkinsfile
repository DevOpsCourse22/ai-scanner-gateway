// CI for ai-scanner-gateway.
//
// What it does, in order:
//   1. Test     run the gateway's test suite
//   2. Build    build the review-gateway image into a tar file
//   3. Scan     Trivy scans it; a fixable CRITICAL vulnerability fails the build
//   4. Push     push it to the registry (main branch only)
//   5. Deploy   commit the new tag to ai-scanner-gateway-deployment (main only);
//               Argo CD sees the commit and rolls the cluster to it
//
// Registry and credentials: the same Jenkins global variables and credentials
// as ai-scanner-backend's Jenkinsfile (REGISTRY_KIND, REGISTRY, AWS_REGION,
// AWS_CREDENTIALS_ID; credential github-deploy). See its header.

def IMAGES = [
    [name: 'review-gateway', args: '--local context=. --local dockerfile=.'],
]

pipeline {
    agent {
        kubernetes {
            yamlFile 'ci/pod.yaml'
            defaultContainer 'python'
        }
    }
    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }
    environment {
        REGISTRY_KIND = "${env.REGISTRY_KIND ?: 'local'}"
        REGISTRY      = "${env.REGISTRY ?: '10.0.0.39:30500'}"
        TAG           = "${env.GIT_COMMIT.take(7)}"
        DEPLOY_REPO   = 'DevOpsCourse22/ai-scanner-gateway-deployment'
    }

    stages {
        stage('Test') {
            steps {
                container('python') {
                    sh '''
                        python -m pip install --quiet --upgrade pip
                        python -m pip install --quiet -e ".[dev]"
                        mkdir -p test-results
                        python -m pytest -q --junitxml=test-results/gateway.xml
                    '''
                }
            }
            post { always { junit 'test-results/*.xml' } }
        }

        stage('Build') {
            steps {
                container('buildkit') {
                    script {
                        for (img in IMAGES) {
                            sh """
                                buildctl-daemonless.sh build --frontend dockerfile.v0 ${img.args} \
                                  --output type=docker,name=${REGISTRY}/${img.name}:${TAG},dest=${img.name}.tar
                            """
                        }
                    }
                }
            }
        }

        stage('Scan') {
            steps {
                container('trivy') {
                    script {
                        for (img in IMAGES) {
                            sh "trivy image --quiet --input ${img.name}.tar --severity HIGH,CRITICAL --ignore-unfixed --format table --output trivy-${img.name}.txt"
                            sh "trivy image --quiet --input ${img.name}.tar --severity CRITICAL --ignore-unfixed --exit-code 1"
                        }
                    }
                }
            }
            post { always { archiveArtifacts artifacts: 'trivy-*.txt', allowEmptyArchive: true } }
        }

        stage('Push') {
            when { branch 'main' }
            steps {
                script {
                    if (env.REGISTRY_KIND == 'ecr') { ecrLogin() }
                    def insecure = env.REGISTRY_KIND == 'local' ? ',registry.insecure=true' : ''
                    container('buildkit') {
                        for (img in IMAGES) {
                            sh """
                                buildctl-daemonless.sh build --frontend dockerfile.v0 ${img.args} \
                                  --output type=image,name=${REGISTRY}/${img.name}:${TAG},push=true${insecure}
                            """
                        }
                    }
                }
            }
        }

        stage('Deploy') {
            when {
                allOf { branch 'main'; expression { env.UPDATE_DEPLOY_REPO != 'false' } }
            }
            steps {
                container('git') {
                    withCredentials([usernamePassword(credentialsId: 'github-deploy',
                                                      usernameVariable: 'GIT_USER', passwordVariable: 'GIT_PASS')]) {
                        sh '''
                            set -eu
                            . ci/deploy-lib.sh
                            clone_deploy_repo
                            set_image review-gateway kustomization.yaml
                            commit_and_push "review-gateway"
                        '''
                    }
                }
            }
        }
    }

    post {
        always { sh 'rm -f *.tar .ecr-password' }
    }
}

// ECR has no fixed password: ask AWS for a 12-hour token and write it where BuildKit looks for logins.
def ecrLogin() {
    def body = {
        container('aws') {
            sh 'aws ecr get-login-password --region "$AWS_REGION" > .ecr-password'
        }
        container('buildkit') {
            sh '''
                mkdir -p "$HOME/.docker"
                AUTH=$(printf 'AWS:%s' "$(cat .ecr-password)" | base64 | tr -d '\\n')
                printf '{"auths":{"%s":{"auth":"%s"}}}' "$REGISTRY" "$AUTH" > "$HOME/.docker/config.json"
                rm -f .ecr-password
            '''
        }
    }
    if (env.AWS_CREDENTIALS_ID) {
        withCredentials([usernamePassword(credentialsId: env.AWS_CREDENTIALS_ID,
                                          usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
            body()
        }
    } else {
        body()
    }
}
