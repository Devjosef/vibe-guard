// Jenkins Pipeline definition
pipeline {
    // Define the agent (executor) for the pipeline
    agent {
        docker {
            image 'docker:20.10.16'  // Base Docker image for all stages
            args '-v /var/run/docker.sock:/var/run/docker.sock'  // Mount Docker socket for Docker-in-Docker
        }
    }

    // Global pipeline options
    options {
        timeout(time: 10, unit: 'MINUTES')  // Prevent hanging jobs
        disableConcurrentBuilds()  // Ensure only one build runs at a time
        ansiColor('xterm')  // Enable colored console output
    }

    // Environment variables available to all stages
    environment {
        DOCKER_REGISTRY = 'your-registry'  // Docker registry URL
        DOCKER_IMAGE = 'vibe-guard'        // Docker image name
        DOCKER_CREDENTIALS = credentials('docker-credentials')  // Secure credentials binding
        DOCKER_BUILDKIT = 1  // Enable BuildKit for faster builds
    }

    // Pipeline stages
    stages {
        // Test stage: Verify application functionality
        stage('Test') {
            steps {
                sh '''
                    docker build -t ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER} .
                    docker run --rm ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER} vibe-guard --version
                    docker run --rm ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER} vibe-guard scan --help
                '''
            }
            // Post-build actions for test stage
            post {
                always {
                    junit 'test-results/*.xml'  // Publish test results
                }
            }
        }

        // Security scanning stage
        stage('Security Scan') {
            steps {
                sh '''
                    docker run --rm ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER} vibe-guard scan .
                '''
            }
            // Archive security report
            post {
                always {
                    archiveArtifacts artifacts: 'security-report.json', allowEmptyArchive: true
                }
            }
        }

        // Build stage: Create Docker image
        stage('Build') {
            steps {
                sh '''
                    docker build -t ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER} .
                    docker tag ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER} ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:latest
                '''
            }
        }

        // Push stage: Upload images to registry
        stage('Push') {
            steps {
                sh '''
                    echo ${DOCKER_CREDENTIALS} | docker login ${DOCKER_REGISTRY} -u ${DOCKER_CREDENTIALS_USR} --password-stdin
                    docker push ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER}
                    docker push ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:latest
                '''
            }
        }

        // Deploy stage: Deploy to production
        stage('Deploy') {
            when {
                branch 'main'  // Only deploy from main branch
            }
            steps {
                sh '''
                    docker-compose pull
                    docker-compose up -d
                '''
            }
        }

        // Multi-architecture build stage
        stage('Multi-arch Build') {
            parallel {  // Run architecture builds in parallel
                // AMD64 (x86_64) architecture build
                stage('Build AMD64') {
                    agent {
                        docker {
                            image 'tonistiigi/binfmt:qemu-v7.0.0'  // QEMU for cross-platform builds
                            args '--privileged'  // Required for QEMU
                        }
                    }
                    steps {
                        sh '''
                            docker run --privileged --rm tonistiigi/binfmt --install all
                            docker buildx create --use
                            docker buildx build --platform linux/amd64 
                                -t ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER}-amd64 
                                -t ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:latest-amd64 
                                --push .
                        '''
                    }
                }

                // ARM64 architecture build
                stage('Build ARM64') {
                    agent {
                        docker {
                            image 'tonistiigi/binfmt:qemu-v7.0.0'
                            args '--privileged'
                        }
                    }
                    steps {
                        sh '''
                            docker run --privileged --rm tonistiigi/binfmt --install all
                            docker buildx create --use
                            docker buildx build --platform linux/arm64 
                                -t ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER}-arm64 
                                -t ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:latest-arm64 
                                --push .
                        '''
                    }
                }

                // ARMv7 architecture build
                stage('Build ARMV7') {
                    agent {
                        docker {
                            image 'tonistiigi/binfmt:qemu-v7.0.0'
                            args '--privileged'
                        }
                    }
                    steps {
                        sh '''
                            docker run --privileged --rm tonistiigi/binfmt --install all
                            docker buildx create --use
                            docker buildx build --platform linux/arm/v7 
                                -t ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${BUILD_NUMBER}-armv7 
                                -t ${DOCKER_REGISTRY}/${DOCKER_IMAGE}:latest-armv7 
                                --push .
                        '''
                    }
                }
            }
        }
    }

    // Post-build actions for the entire pipeline
    post {
        always {
            cleanWs()  // Clean workspace after build
            script {
                // Send email notifications based on build result
                if (currentBuild.currentResult == 'SUCCESS') {
                    emailext (
                        subject: "Pipeline Successful: ${currentBuild.fullDisplayName}",
                        body: "Check console output at ${env.BUILD_URL}",
                        to: 'team@example.com'
                    )
                } else {
                    emailext (
                        subject: "Pipeline Failed: ${currentBuild.fullDisplayName}",
                        body: "Check console output at ${env.BUILD_URL}",
                        to: 'team@example.com'
                    )
                }
            }
        }
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
} 