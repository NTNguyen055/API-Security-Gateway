pipeline {
    agent any

    environment {
        IMAGE_NAME = 'ntnguyen055/api-security-app'
        IMAGE_TAG  = "v${env.BUILD_NUMBER}"

        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'

        // ĐƯỜNG DẪN THỰC TẾ TRÊN EC2 CỦA BẠN
        EC2_APP_IP = '18.179.59.156' 
        EC2_USER   = 'ubuntu'
        // Thư mục chứa code dự án
        APP_DIR    = '/home/ubuntu/appointment-web/API-Security-Gateway'
        // Đường dẫn file .env nằm ở thư mục cha
        ENV_PATH   = '/home/ubuntu/appointment-web/.env'
    }

    stages {
        stage('1. Checkout SCM') {
            steps {
                checkout scm
            }
        }

        stage('2. Build & Push Image') {
            steps {
                echo "Đang build version ${IMAGE_TAG}..."
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -t ${IMAGE_NAME}:latest ./docappsystem"
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                sh "docker push ${IMAGE_NAME}:${IMAGE_TAG}"
                sh "docker push ${IMAGE_NAME}:latest"
            }
        }

        stage('3. Sync Config & Deploy') {
            steps {
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    // 1. Tạo thư mục nếu chưa có và đẩy docker-compose.yml mới nhất sang
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} 'mkdir -p ${APP_DIR}'
                    scp -o StrictHostKeyChecking=no docker-compose.yml ${EC2_USER}@${EC2_APP_IP}:${APP_DIR}/docker-compose.yml
                    """

                    // 2. Chạy lệnh Deploy với file .env từ thư mục cha
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        cd ${APP_DIR}
                        
                        echo "--- [1] SAO LƯU TAG ---"
                        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:previous || true
                        
                        echo "--- [2] PULL IMAGE MỚI ---"
                        docker compose pull app
                        
                        echo "--- [3] KHỞI CHẠY (Sử dụng .env từ thư mục cha) ---"
                        # Chỉ định file .env nằm ở ngoài thư mục hiện tại
                        docker compose --env-file ${ENV_PATH} up -d app
                        
                        echo "--- [4] KIỂM TRA SỨC KHỎE (10s) ---"
                        sleep 10
                        IS_RUNNING=\$(docker inspect -f "{{.State.Running}}" docapp_django)
                        
                        if [ "\$IS_RUNNING" != "true" ]; then
                            echo "⚠️ LỖI: Container không chạy! Đang Rollback..."
                            docker compose --env-file ${ENV_PATH} down app
                            docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest
                            docker compose --env-file ${ENV_PATH} up -d app
                            exit 1
                        else
                            echo "✅ Triển khai thành công version ${IMAGE_TAG}"
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
    }
}