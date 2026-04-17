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
        stage('🚀 Checkout') {
            steps { checkout scm }
        }

        stage('📦 Build Image') {
            steps {
                sh """
                docker build -t ${IMAGE_NAME}:${IMAGE_TAG} \
                             -t ${IMAGE_NAME}:latest \
                             ./docappsystem
                """
            }
        }

        stage('☁️ Push Image') {
            steps {
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                sh """
                docker push ${IMAGE_NAME}:${IMAGE_TAG}
                docker push ${IMAGE_NAME}:latest
                """
            }
        }

        stage('🚢 Deploy & Rollback') {
            steps {
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        mkdir -p ${BASE_DIR}
                        cd ${BASE_DIR}

                        echo "--- [1] KÉO MÃ NGUỒN MỚI TỪ GITHUB ---"
                        if [ ! -d API-Security-Gateway ]; then
                            git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git
                        else
                            cd API-Security-Gateway && git pull origin main
                        fi

                        cd ${APP_DIR}

                        if [ ! -f ${ENV_PATH} ]; then
                            echo "❌ LỖI: Không tìm thấy file .env"
                            exit 1
                        fi

                        echo "--- [2] SAO LƯU BẢN CŨ ---"
                        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:previous || true

                        echo "--- [3] TẢI & KHỞI CHẠY HỆ THỐNG MỚI ---"
                        # Pull mới toàn bộ (cả App và OpenResty Gateway nếu có)
                        docker compose --env-file ${ENV_PATH} pull
                        # Khởi chạy và xóa bỏ các container rác không còn dùng
                        docker compose --env-file ${ENV_PATH} up -d --remove-orphans

                        echo "--- [4] KIỂM TRA SỨC KHỎE (15s) ---"
                        sleep 15

                        # Lấy trạng thái của 2 container chính
                        STATUS_APP=\$(docker inspect -f "{{.State.Running}}" docapp_django || echo "false")
                        STATUS_GW=\$(docker inspect -f "{{.State.Running}}" openresty_gateway || echo "false")

                        if [ "\$STATUS_APP" != "true" ] || [ "\$STATUS_GW" != "true" ]; then
                            echo "⚠️ LỖI: Phát hiện Container bị crash! Tiến hành Rollback..."
                            docker compose --env-file ${ENV_PATH} down
                            docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest
                            docker compose --env-file ${ENV_PATH} up -d
                            exit 1
                        else
                            echo "✅ Dịch vụ Web & Gateway hoạt động ổn định."
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