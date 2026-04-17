pipeline {
    agent any

    environment {
        IMAGE_NAME = 'ntnguyen055/api-security-app'
        IMAGE_TAG  = "v${env.BUILD_NUMBER}"

        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'

        EC2_HOST = 'ubuntu@35.76.108.185'

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
                echo "📤 Push Docker Image"

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

                    // 🔧 Setup server + repo
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_HOST} '
                        sudo mkdir -p ${BASE_DIR}
                        sudo chown -R ubuntu:ubuntu ${BASE_DIR}

                        cd ${BASE_DIR}

                        if [ ! -d "API-Security-Gateway" ]; then
                            echo "📥 Clone repo..."
                            git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git
                        else
                            echo "🔄 Pull latest code..."
                            cd API-Security-Gateway && git pull
                        fi
                    '
                    """

                    // 📄 Copy docker-compose
                    sh """
                    scp -o StrictHostKeyChecking=no docker-compose.yml \
                    ${EC2_HOST}:${APP_DIR}/
                    """

                    // 🚀 Deploy + rollback
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_HOST} '
                        cd ${APP_DIR}

                        echo "🧱 Backup current image"
                        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:previous || true

                        echo "⬇️ Pull latest image"
                        docker-compose pull app

                        echo "🚀 Start container"
                        docker-compose up -d app

                        echo "⏳ Waiting for health check..."
                        sleep 10

                        CONTAINER_NAME=docapp_django
                        IS_RUNNING=\$(docker inspect -f "{{.State.Running}}" \$CONTAINER_NAME 2>/dev/null || echo "false")

                        if [ "\$IS_RUNNING" != "true" ]; then
                            echo "❌ Deploy failed → rollback"

                            docker-compose down

                            docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest

                            docker-compose up -d app

                            echo "🔄 Rollback completed"
                            exit 1
                        fi

                        echo "✅ Deploy success"
                        docker image prune -f
                    '
                    """
                }
            }
        }
    }

    post {
        always {
            sh 'docker image prune -f || true'
            sh 'docker logout || true'
        }
        success {
            echo "🎉 SUCCESS: ${IMAGE_TAG} deployed"
        }
        failure {
            echo "❌ FAILED: Check logs / rollback executed"
        }
    }
}