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

        stage('Build Docker Image') {
            steps {
                echo "🚀 Build ${IMAGE_TAG}"

                    sh """
                    docker build -t ${IMAGE_NAME}:${IMAGE_TAG} \
                                -t ${IMAGE_NAME}:latest \
                                ./docappsystem
                    """
            }
        }

        stage('Push Docker Image') {
            steps {
                echo "📦 Push image"

                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'

                sh """
                docker push ${IMAGE_NAME}:${IMAGE_TAG}
                docker push ${IMAGE_NAME}:latest
                """
            }
        }

        stage('Deploy to EC2') {
            steps {
                sshagent(credentials: [EC2_SSH_CREDS]) {

                    // 🔥 FIX QUYỀN + đảm bảo folder tồn tại
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        sudo mkdir -p ${BASE_DIR}
                        sudo chown -R ${EC2_USER}:${EC2_USER} ${BASE_DIR}
                        sudo chmod -R 755 ${BASE_DIR}
                    '
                    """

                    // 🔥 Clone hoặc pull repo
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        cd ${BASE_DIR}

                        if [ ! -d "API-Security-Gateway" ]; then
                            echo "📥 Clone repo..."
                            git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git
                        else
                            echo "🔄 Pull code..."
                            cd API-Security-Gateway && git pull
                        fi
                    '
                    """

                    // 🔥 Copy docker-compose
                    sh """
                    scp -o StrictHostKeyChecking=no docker-compose.yml \
                    ${EC2_USER}@${EC2_APP_IP}:${APP_DIR}/
                    """

                    // 🚀 Deploy + rollback
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        cd ${APP_DIR}

                        echo "🧱 Backup image"
                        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:previous || true

                        echo "⬇️ Pull image mới"
                        docker compose --env-file ${ENV_PATH} pull app

                        echo "🚀 Start container"
                        docker compose --env-file ${ENV_PATH} up -d app

                        echo "⏳ Health check (10s)..."
                        sleep 10

                        IS_RUNNING=\$(docker inspect -f "{{.State.Running}}" docapp_django 2>/dev/null || echo "false")

                        if [ "\$IS_RUNNING" != "true" ]; then
                            echo "❌ Container lỗi → rollback"

                            docker compose down

                            docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest

                            docker compose --env-file ${ENV_PATH} up -d app

                            echo "🔄 Rollback xong"
                            exit 1
                        else
                            echo "✅ Deploy thành công"
                            docker image prune -f
                        fi
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
            echo "🎉 Deploy thành công: ${IMAGE_TAG}"
        }
        failure {
            echo "❌ Pipeline fail → đã rollback hoặc cần kiểm tra log"
        }
    }
}