pipeline {
    agent any

    environment {
        APP_IMAGE = 'ntnguyen055/api-security-app'
        GW_IMAGE  = 'ntnguyen055/api-security-gateway'
        IMAGE_TAG = "v${BUILD_NUMBER}"

        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'
        EC2_APP_IP      = '35.76.108.185'  

        EC2_USER = 'ubuntu'
        BASE_DIR = '/home/ubuntu/appointment-web'
        APP_DIR  = '/home/ubuntu/appointment-web/API-Security-Gateway'
        ENV_PATH = '/home/ubuntu/appointment-web/.env'
    }

    stages {

        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Build Images') {
            steps {
                sh """
                docker build -t ${APP_IMAGE}:${IMAGE_TAG} \
                             -t ${APP_IMAGE}:latest \
                             ./docappsystem

                docker build --no-cache \
                             -t ${GW_IMAGE}:${IMAGE_TAG} \
                             -t ${GW_IMAGE}:latest \
                             ./nginx
                """
            }
        }

        stage('Test') {
            steps {
                // Chạy Django test trong container tạm — dùng SQLite để không cần RDS
                sh """
                docker run --rm \
                    --entrypoint "" \
                    -e DEBUG=True \
                    -e SECRET_KEY=ci-test-key-not-used-in-prod \
                    -e JWT_SECRET_KEY=ci-jwt-key \
                    -e DB_ENGINE=django.db.backends.sqlite3 \
                    -e DB_NAME=/tmp/test.db \
                    ${APP_IMAGE}:${IMAGE_TAG} \
                    python manage.py test --verbosity=2
                """
            }
        }

        stage('Push Images') {
            steps {
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                sh """
                docker push ${APP_IMAGE}:${IMAGE_TAG}
                docker push ${APP_IMAGE}:latest
                docker push ${GW_IMAGE}:${IMAGE_TAG}
                docker push ${GW_IMAGE}:latest
                """
            }
        }

        stage('Deploy & Rollback') {
            steps {
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        mkdir -p ${BASE_DIR}

                        echo "--- [1] PULL CODE ---"
                        if [ ! -d ${APP_DIR} ]; then
                            git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git ${APP_DIR}
                        else
                            cd ${APP_DIR} && git pull origin main
                        fi

                        cd ${APP_DIR}

                        if [ ! -f ${ENV_PATH} ]; then
                            echo "ERROR: .env not found at ${ENV_PATH}"
                            exit 1
                        fi

                        echo "--- [2] BACKUP IMAGE TAG ---"
                        docker tag ${APP_IMAGE}:latest ${APP_IMAGE}:previous || true
                        docker tag ${GW_IMAGE}:latest ${GW_IMAGE}:previous || true

                        echo "--- [3] DEPLOY ---"
                        docker compose --env-file ${ENV_PATH} pull
                        docker compose --env-file ${ENV_PATH} up -d --remove-orphans

                        echo "--- [4] HEALTH CHECK (30s) ---"
                        sleep 30

                        STATUS_APP=\$(docker inspect -f "{{.State.Running}}" docapp_django    2>/dev/null || echo "false")
                        STATUS_GW=\$(docker inspect -f  "{{.State.Running}}" openresty_gateway 2>/dev/null || echo "false")

                        HTTP_STATUS=\$(curl -s -o /dev/null -w "%{http_code}" \
                            --max-time 10 http://localhost/health/ || echo "000")

                        echo "Container app: \$STATUS_APP | gateway: \$STATUS_GW | HTTP: \$HTTP_STATUS"

                        if [ "\$STATUS_APP" != "true" ] || [ "\$STATUS_GW" != "true" ] || [ "\$HTTP_STATUS" != "200" ]; then
                            echo "HEALTH CHECK FAILED → ROLLBACK"
                            docker compose down
                            docker tag ${APP_IMAGE}:previous ${APP_IMAGE}:latest || true
                            docker tag ${GW_IMAGE}:previous ${GW_IMAGE}:latest || true
                            docker compose up -d
                            exit 1
                        fi

                        echo "DEPLOY SUCCESS: ${IMAGE_TAG}"
                        docker image prune -f
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
            echo "SUCCESS: ${IMAGE_TAG} deployed"
        }
        failure {
            echo "FAILED: ${IMAGE_TAG} - check logs"
        }
    }
}
