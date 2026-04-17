pipeline {
    agent any

    environment {
        IMAGE_NAME = 'ntnguyen055/api-security-app'
        IMAGE_TAG  = "v${env.BUILD_NUMBER}"

        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'

        EC2_APP_IP = '35.76.108.185'
        EC2_USER   = 'ubuntu'

        APP_DIR  = '/home/ubuntu/appointment-web/API-Security-Gateway'
        BASE_DIR = '/home/ubuntu/appointment-web'
        ENV_PATH = '/home/ubuntu/appointment-web/.env'
    }

    stages {
        stage('1. Kéo mã nguồn') {
            steps {
                checkout scm
            }
        }

        stage('2. Build & Push Docker Image') {
            steps {
                echo "--- BUILD VERSION ${IMAGE_TAG} ---"

                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -t ${IMAGE_NAME}:latest ./docappsystem"

                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'

                sh "docker push ${IMAGE_NAME}:${IMAGE_TAG}"
                sh "docker push ${IMAGE_NAME}:latest"
            }
        }

        stage('3. Deploy & Rollback') {
            steps {
                sshagent(credentials: [EC2_SSH_CREDS]) {

                    // 🔥 FIX 1: đảm bảo folder + repo tồn tại
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        mkdir -p ${BASE_DIR}
                        cd ${BASE_DIR}

                        if [ ! -d "API-Security-Gateway" ]; then
                            echo "Repo chưa tồn tại → clone mới"
                            git clone https://github.com/NTNguyen055/API-Security-Gateway.git
                        else
                            echo "Repo đã tồn tại → pull code mới"
                            cd API-Security-Gateway && git pull
                        fi
                    '
                    """

                    // 🔥 FIX 2: copy docker-compose sau khi folder chắc chắn tồn tại
                    sh """
                    scp -o StrictHostKeyChecking=no docker-compose.yml \
                    ${EC2_USER}@${EC2_APP_IP}:${APP_DIR}/
                    """

                    // 🚀 Deploy + rollback
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        cd ${APP_DIR}

                        echo "[1] Backup image current"
                        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:previous || true

                        echo "[2] Pull image mới"
                        docker compose --env-file ${ENV_PATH} pull app

                        echo "[3] Start container"
                        docker compose --env-file ${ENV_PATH} up -d app

                        echo "[4] Health check..."
                        sleep 10

                        IS_RUNNING=\$(docker inspect -f "{{.State.Running}}" docapp_django || echo "false")

                        if [ "\$IS_RUNNING" != "true" ]; then
                            echo "❌ Container crash → rollback"

                            docker compose --env-file ${ENV_PATH} down

                            docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest

                            docker compose --env-file ${ENV_PATH} up -d app

                            echo "✅ Rollback thành công"
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
            echo "🚀 Version ${IMAGE_TAG} đã deploy thành công!"
        }
        failure {
            echo "❌ Pipeline thất bại. Đã rollback hoặc cần kiểm tra log."
        }
    }
}