pipeline {
    agent any

    environment {
        // 1. Thông tin Image
        IMAGE_NAME = 'ntnguyen055/api-security-app'
        IMAGE_TAG  = "v${env.BUILD_NUMBER}" // Tự động đánh tag theo số thứ tự bản build

        // 2. Credential IDs KHỚP VỚI ẢNH CỦA BẠN
        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'

        // 3. Thông tin máy chủ đích
        EC2_APP_IP = '18.179.59.156' // <--- Sửa dòng này thành IP máy EC2-App
        EC2_USER   = 'ubuntu'                
        // Sửa đường dẫn này thành nơi bạn để file docker-compose.yml trên con EC2-App
        APP_DIR    = '/home/ubuntu/appointment-web/API-Security-Gateway' 
    }

    stages {
        stage('1. Checkout SCM') {
            steps {
                echo 'Đang kéo mã nguồn mới nhất từ nhánh chính của GitHub...'
                checkout scm
            }
        }

        stage('2. Build Docker Image') {
            steps {
                echo 'Đóng gói mã nguồn Django thành Docker Image...'
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -t ${IMAGE_NAME}:latest ."
            }
        }

        stage('3. Push to DockerHub') {
            steps {
                echo 'Đẩy Image lên kho lưu trữ DockerHub...'
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                sh "docker push ${IMAGE_NAME}:${IMAGE_TAG}"
                sh "docker push ${IMAGE_NAME}:latest"
            }
        }

        stage('4. Deploy & Auto-Rollback (EC2-App)') {
            steps {
                echo 'Kết nối SSH vào EC2-App để triển khai bản cập nhật...'
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        # Chui vào đúng thư mục chứa docker-compose.yml
                        cd ${APP_DIR} || exit 1
                        
                        echo "--- [1] BẮT ĐẦU DEPLOY ---"
                        echo "Sao lưu Image hiện tại thành bản previous..."
                        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:previous || true
                        
                        echo "Tải Image mới nhất từ DockerHub..."
                        docker compose pull app
                        
                        echo "Khởi động lại Container Django App..."
                        docker compose up -d app
                        
                        echo "--- [2] KIỂM TRA SỨC KHỎE (HEALTH CHECK) ---"
                        echo "Chờ 10s để hệ thống khởi động..."
                        sleep 10
                        
                        # Kiểm tra trạng thái của container tên là docapp_django
                        IS_RUNNING=\$(docker inspect -f "{{.State.Running}}" docapp_django)
                        
                        if [ "\$IS_RUNNING" != "true" ]; then
                            echo "⚠️ PHÁT HIỆN SỰ CỐ: Container bị crash! Tiến hành Rollback..."
                            docker compose down app
                            docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest
                            docker compose up -d app
                            echo "✅ Đã Rollback thành công về phiên bản trước."
                            exit 1 
                        else
                            echo "✅ Dịch vụ trực tuyến ổn định. Triển khai thành công!"
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
            echo 'Dọn dẹp môi trường Jenkins...'
            sh 'docker image prune -f'
            sh 'docker logout'
        }
        success {
            echo '🎉 CI/CD Pipeline hoàn tất xuất sắc!'
        }
        failure {
            echo '❌ Pipeline thất bại. Vui lòng kiểm tra log.'
        }
    }
}