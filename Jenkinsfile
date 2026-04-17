pipeline {
    agent any

    environment {
        IMAGE_NAME = 'ntnguyen055/api-security-app'
        IMAGE_TAG  = "v${env.BUILD_NUMBER}"

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
                echo "🚀 Building ${IMAGE_TAG}"

                sh """
                docker build -t ${IMAGE_NAME}:${IMAGE_TAG} \
                             -t ${IMAGE_NAME}:latest \
                             ./docappsystem
                """
            }
        }

        stage('📦 Push Image') {
            steps {
                echo "📤 Push to Docker Hub"

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

                        echo "📁 Setup folder"
                        sudo mkdir -p ${BASE_DIR}
                        sudo chown -R ${EC2_USER}:${EC2_USER} ${BASE_DIR}

                        cd ${BASE_DIR}

                        echo "📦 Sync source"
                        if [ ! -d "API-Security-Gateway" ]; then
                            git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git
                        else
                            cd API-Security-Gateway && git pull
                        fi

                        cd ${APP_DIR}

                        echo "📄 Check .env"
                        if [ ! -f ${ENV_PATH} ]; then
                            echo "❌ Missing .env file!"
                            exit 1
                        fi

                        echo "🧱 Backup image"
                        docker image inspect ${IMAGE_NAME}:latest > /dev/null 2>&1 && \
                        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:previous || true

                        echo "🧹 Clean old containers"
                        docker compose down || true

                        echo "🧹 Remove orphan container (if exists)"
                        docker rm -f docapp_django || true

                        echo "⬇️ Pull latest image"
                        docker compose pull app

                        echo "🚀 Start container"
                        docker compose up -d app

                        echo "⏳ Wait for app (15s)"
                        sleep 15

                        echo "🌐 Health check"
                        STATUS=\$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000 || true)

                        if [ "\$STATUS" != "200" ]; then
                            echo "❌ App failed (HTTP \$STATUS) → rollback"

                            docker compose down

                            docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest || true

                            docker compose up -d app

                            exit 1
                        fi

                        echo "✅ Deploy success"
                        docker image prune -f
                    '
                    """
                }
            }
        }

    post {
        always {
            sh 'docker image prune -f || true'
            sh 'docker logout || true'
        }
        success {
            echo "🎉 SUCCESS: ${IMAGE_TAG}"
        }
        failure {
            echo "❌ FAILED: Check logs / rollback executed"
        }
    }
}