pipeline {
    agent any

    environment {
        IMAGE_NAME = 'ntnguyen055/api-security-app'
        IMAGE_TAG  = "v${BUILD_NUMBER}"

        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'

        EC2_APP_IP = '35.76.108.185'
        EC2_USER   = 'ubuntu'

        BASE_DIR = '/home/ubuntu/appointment-web'
        APP_DIR  = '/home/ubuntu/appointment-web/API-Security-Gateway'
        ENV_PATH = '/home/ubuntu/appointment-web/.env'
    }

    stages {

        stage('📥 Checkout') {
            steps {
                checkout scm
            }
        }

        stage('🐳 Build Image') {
            steps {
                sh """
                docker build -t ${IMAGE_NAME}:${IMAGE_TAG} \
                             -t ${IMAGE_NAME}:latest \
                             ./docappsystem
                """
            }
        }

        stage('📦 Push Image') {
            steps {
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                sh """
                docker push ${IMAGE_NAME}:${IMAGE_TAG}
                docker push ${IMAGE_NAME}:latest
                """
            }
        }

        stage('🚀 Deploy') {
            steps {
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        set -e

                        mkdir -p ${BASE_DIR}
                        cd ${BASE_DIR}

                        if [ ! -d API-Security-Gateway ]; then
                            git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git
                        else
                            cd API-Security-Gateway && git pull
                        fi

                        cd ${APP_DIR}

                        if [ ! -f ${env.ENV_PATH} ]; then
                            echo "Missing .env file"
                            exit 1
                        fi

                        docker compose down || true
                        docker rm -f docapp_django || true
                        docker rm -f docapp_redis || true

                        docker compose pull app
                        docker compose up -d

                        sleep 15

                        STATUS=\$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000 || true)

                        if [ "\$STATUS" != "200" ]; then
                            docker compose logs
                            exit 1
                        fi
                    '
                    """
                }
            }
        }
    }

    post {
        always {
            sh 'docker logout || true'
        }

        success {
            echo "🎉 SUCCESS: ${IMAGE_TAG}"
        }

        failure {
            echo "❌ FAILED"
        }
    }
}