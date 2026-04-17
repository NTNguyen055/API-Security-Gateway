pipeline {
    agent any

    environment {
        // 1. Thông tin Docker Image
        IMAGE_NAME = 'ntnguyen055/api-security-app'
        IMAGE_TAG  = "v${env.BUILD_NUMBER}"

        // 2. Credential IDs khớp với Jenkins của bạn
        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'

        // 3. Thông tin hạ tầng thực tế của bạn
        EC2_APP_IP = '35.76.108.185' // Thay bằng IP Public của EC2-App
        EC2_USER   = 'ubuntu'
        APP_DIR    = '/home/ubuntu/appointment-web/API-Security-Gateway'
        ENV_PATH   = '/home/ubuntu/appointment-web/.env'
    }

    stages {
        stage('1. Kéo mã nguồn') {
            steps {
                checkout scm
            }
        }

        stage('2. Đóng gói & Đẩy lên Docker Hub') {
            steps {
                echo "--- BẮT ĐẦU BUILD VERSION ${IMAGE_TAG} ---"
                // Build chui vào thư mục docappsystem để lấy Dockerfile
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -t ${IMAGE_NAME}:latest ./docappsystem"
                
                echo "--- ĐĂNG NHẬP DOCKER HUB ---"
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                
                echo "--- PUSH IMAGE ---"
                sh "docker push ${IMAGE_NAME}:${IMAGE_TAG}"
                sh "docker push ${IMAGE_NAME}:latest"
            }
        }

        stage('3. Triển khai & Tự động Rollback') {
            steps {
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    // Cập nhật docker-compose.yml mới nhất sang EC2
                    sh "scp -o StrictHostKeyChecking=no docker-compose.yml ${EC2_USER}@${EC2_APP_IP}:${APP_DIR}/docker-compose.yml"

                    // Chạy script Bash trên EC2 để thực hiện Deploy + Health Check
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        cd ${APP_DIR}
                        
                        echo "[Step 1] Sao lưu Image hiện tại làm bản dự phòng (previous)..."
                        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:previous || true
                        
                        echo "[Step 2] Tải Image mới nhất về..."
                        docker compose --env-file ${ENV_PATH} pull app
                        
                        echo "[Step 3] Khởi động bản cập nhật..."
                        docker compose --env-file ${ENV_PATH} up -d app
                        
                        echo "[Step 4] Chờ 10 giây để kiểm tra sức khỏe hệ thống..."
                        sleep 10
                        
                        # Kiểm tra xem Container có thực sự đang chạy (Running) không
                        IS_RUNNING=\$(docker inspect -f "{{.State.Running}}" docapp_django)
                        
                        if [ "\$IS_RUNNING" != "true" ]; then
                            echo "PHÁT HIỆN SỰ CỐ: Container đã bị crash sau khi khởi động!"
                            echo "--- TIẾN HÀNH AUTO-ROLLBACK ---"
                            docker compose --env-file ${ENV_PATH} down app
                            # Đổi tag bản previous quay lại thành latest
                            docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest
                            docker compose --env-file ${ENV_PATH} up -d app
                            echo "Đã khôi phục phiên bản ổn định thành công."
                            exit 1 # Báo lỗi cho Jenkins Pipeline
                        else
                            echo "Phiên bản mới hoạt động ổn định. Triển khai hoàn tất!"
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
        success { echo "Tuyệt vời! Version ${IMAGE_TAG} đã online." }
        failure { echo "Pipeline thất bại. Hệ thống đã được Rollback hoặc cần kiểm tra log." }
    }
}