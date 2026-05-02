pipeline {
    agent any

    environment {
        // --- CẤU HÌNH IMAGE ---
        APP_IMAGE = 'ntnguyen055/api-security-app'
        GW_IMAGE  = 'ntnguyen055/api-security-gateway'
        IMAGE_TAG = "v${BUILD_NUMBER}"
        
        // --- BẬT DOCKER BUILDKIT ĐỂ BUILD NHANH HƠN ---
        DOCKER_BUILDKIT = 1

        // --- THÔNG TIN DEPLOY ---
        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'
        EC2_APP_IP      = '13.159.56.185'
        EC2_USER        = 'ubuntu'
        
        // --- ĐƯỜNG DẪN TRÊN EC2 ---
        BASE_DIR = '/home/ubuntu/appointment-web'
        APP_DIR  = '/home/ubuntu/appointment-web/API-Security-Gateway'
        ENV_PATH = '/home/ubuntu/appointment-web/.env'
    }

    stages {
        stage('Checkout Code') {
            steps { 
                checkout scm 
            }
        }

        stage('Build & Verify Images') {
            steps {
                echo "🚀 Building images with BuildKit..."
                // Build Django App (Tận dụng cache layer của Multi-stage)
                sh """
                docker build --cache-from ${APP_IMAGE}:latest \
                             -t ${APP_IMAGE}:${IMAGE_TAG} \
                             -t ${APP_IMAGE}:latest \
                             ./docappsystem
                """

                // Build OpenResty Gateway (Lỗi cú pháp Nginx sẽ FAILED ngay tại đây)
                sh """
                docker build --cache-from ${GW_IMAGE}:latest \
                             -t ${GW_IMAGE}:${IMAGE_TAG} \
                             -t ${GW_IMAGE}:latest \
                             ./nginx
                """
            }
        }

        stage('Push to DockerHub') {
            steps {
                echo "🐳 Pushing images to DockerHub..."
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                sh """
                docker push ${APP_IMAGE}:${IMAGE_TAG}
                docker push ${APP_IMAGE}:latest
                docker push ${GW_IMAGE}:${IMAGE_TAG}
                docker push ${GW_IMAGE}:latest
                """
            }
        }

        stage('Deploy & Smart Rollback') {
            steps {
                echo "🚢 Deploying to EC2 via SSH..."
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    // Dùng EOF để truyền an toàn script bash qua SSH
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} 'bash -s' << 'EOF'
                        set -e

                        echo "--- [1] PREPARE DIRECTORIES & SYNC CODE ---"
                        mkdir -p "${BASE_DIR}"
                        
                        if [ ! -d "${APP_DIR}" ]; then
                            git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git "${APP_DIR}"
                        else
                            cd "${APP_DIR}"
                            git fetch origin
                            git reset --hard origin/main
                            git clean -fd
                        fi

                        cd "${APP_DIR}"

                        if [ ! -f "${ENV_PATH}" ]; then
                            echo "❌ ERROR: .env file not found at ${ENV_PATH}"
                            exit 1
                        fi

                        echo "--- [2] BACKUP CURRENT RUNNING IMAGES ---"
                        docker tag ${APP_IMAGE}:latest ${APP_IMAGE}:backup 2>/dev/null || true
                        docker tag ${GW_IMAGE}:latest  ${GW_IMAGE}:backup 2>/dev/null || true

                        echo "--- [3] PULL LATEST IMAGES ---"
                        docker compose --env-file "${ENV_PATH}" pull

                        echo "--- [4] DEPLOY & HEALTH CHECK ---"
                        # Vũ khí bí mật: --wait tự động chờ container 'healthy'
                        if ! docker compose --env-file "${ENV_PATH}" up -d --wait --remove-orphans; then
                            echo "⚠️ DEPLOY FAILED OR HEALTHCHECK TIMEOUT! INITIATING ROLLBACK..."
                            
                            docker compose --env-file "${ENV_PATH}" down
                            
                            # Restore tags
                            docker tag ${APP_IMAGE}:backup ${APP_IMAGE}:latest 2>/dev/null || true
                            docker tag ${GW_IMAGE}:backup  ${GW_IMAGE}:latest 2>/dev/null || true
                            
                            echo "🔄 ROLLING BACK TO PREVIOUS VERSION..."
                            docker compose --env-file "${ENV_PATH}" up -d --wait
                            
                            echo "❌ ROLLBACK COMPLETE. DEPLOYMENT MARKED AS FAILED."
                            exit 1
                        fi

                        echo "✅ DEPLOYMENT SUCCESSFUL!"

                        echo "--- [5] CLEANUP ---"
                        # Xóa các image cũ lơ lửng để tránh đầy ổ cứng server
                        docker image prune -af --filter "until=24h"
                    EOF
                    """
                }
            }
        }
    }

    post {
        always {
            sh 'docker logout || true'
            // Xóa image build tạm trên máy Jenkins để giải phóng dung lượng
            sh "docker rmi ${APP_IMAGE}:${IMAGE_TAG} ${APP_IMAGE}:latest ${GW_IMAGE}:${IMAGE_TAG} ${GW_IMAGE}:latest || true"
        }
        success {
            echo "🎉 Pipeline completed successfully!"
        }
        failure {
            echo "🔥 Pipeline failed. Please check the logs."
        }
    }
}