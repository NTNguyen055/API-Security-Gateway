pipeline {
    agent any

    environment {
        // 1. Thông tin Image
        IMAGE_NAME = 'ntnguyen055/api-security-app'
        IMAGE_TAG  = "v${env.BUILD_NUMBER}"

        // 2. Credential IDs đã tạo trên Jenkins
        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'

        // 3. Thông tin máy chủ đích
        EC2_APP_IP = '18.179.59.156' // <--- Nhớ thay IP máy EC2-App vào đây
        EC2_USER   = 'ubuntu'                
        APP_DIR    = '/home/ubuntu/appointment-web/API-Security-Gateway' 
    }

    stages {
        stage('1. Checkout SCM') {
            steps {
                echo 'Đang kéo mã nguồn mới nhất từ GitHub...'
                checkout scm
            }
        }

        stage('2. Build Docker Image') {
            steps {
                echo 'Đóng gói mã nguồn từ thư mục docappsystem/ ...'
                // Dùng ./docappsystem ở cuối lệnh để báo Docker chui vào thư mục đó tìm Dockerfile
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -t ${IMAGE_NAME}:latest ./docappsystem"
            }
        }

        stage('3. Push to DockerHub') {
            steps {
                echo 'Đẩy Image lên DockerHub...'
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                sh "docker push ${IMAGE_NAME}:${IMAGE_TAG}"
                sh "docker push ${IMAGE_NAME}:latest"
            }
        }

        stage('4. Deploy & Auto-Rollback (EC2-App)') {
            steps {
                echo 'Kết nối SSH và tự động hóa triển khai...'
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    
                    // BƯỚC MỚI: Tự động copy file docker-compose.yml từ GitHub sang EC2-App
                    // Giúp bạn không bao giờ phải vào EC2 sửa file compose bằng tay nữa
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} 'mkdir -p ${APP_DIR}'
                    scp -o StrictHostKeyChecking=no docker-compose.yml ${EC2_USER}@${EC2_APP_IP}:${APP_DIR}/docker-compose.yml
                    """

                    // BƯỚC DEPLOY & KIỂM TRA SỨC KHỎE
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        cd ${APP_DIR} || exit 1
                        
                        echo "--- [1] BẮT ĐẦU DEPLOY ---"
                        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:previous || true
                        docker compose pull app
                        docker compose up -d app
                        
                        echo "--- [2] KIỂM TRA SỨC KHỎE (10s) ---"
                        sleep 10
                        
                        IS_RUNNING=\$(docker inspect -f "{{.State.Running}}" docapp_django)
                        
                        if [ "\$IS_RUNNING" != "true" ]; then
                            echo "⚠️ PHÁT HIỆN SỰ CỐ: Tiến hành Rollback..."
                            docker compose down app
                            docker tag ${IMAGE_NAME}:previous ${IMAGE_NAME}:latest
                            docker compose up -d app
                            exit 1 
                        else
                            echo "✅ Dịch vụ ổn định. Triển khai thành công!"
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
            echo 'Dọn dẹp rác trên Jenkins...'
            sh 'docker image prune -f || true'
            sh 'docker logout || true'
        }
    }
}