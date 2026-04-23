pipeline {
    agent any

    environment {
        APP_IMAGE = 'ntnguyen055/api-security-app'
        GW_IMAGE  = 'ntnguyen055/api-security-gateway'
        IMAGE_TAG = "v${BUILD_NUMBER}"

        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'
        EC2_APP_IP      = '35.78.233.182'

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
                docker builder prune -f

                docker build -t ${APP_IMAGE}:${IMAGE_TAG} \
                             -t ${APP_IMAGE}:latest \
                             ./docappsystem

                docker build \
                             -t ${GW_IMAGE}:${IMAGE_TAG} \
                             -t ${GW_IMAGE}:latest \
                             ./nginx
                """
            }
        }

        stage('Test (optional)') {
            steps {
                sh """
                echo "Running Django tests (optional)..."

                OUTPUT=\$(docker run --rm \
                    --entrypoint "" \
                    -e DEBUG=True \
                    -e SECRET_KEY=test-key \
                    -e JWT_SECRET_KEY=test-jwt \
                    -e DB_ENGINE=django.db.backends.sqlite3 \
                    -e DB_NAME=/tmp/test.db \
                    ${APP_IMAGE}:${IMAGE_TAG} \
                    python manage.py test --verbosity=2 2>&1 || true)

                echo "\$OUTPUT"

                # ❌ Fail chỉ khi test FAILED thật
                echo "\$OUTPUT" | grep -q "FAILED" && exit 1 || true
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

        stage('Deploy & Smart Rollback') {
            steps {
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} '
                        set -e

                        mkdir -p ${BASE_DIR}

                        echo "--- [1] PULL CODE ---"
                        if [ ! -d ${APP_DIR} ]; then
                            git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git ${APP_DIR}
                        else
                            cd ${APP_DIR} && git pull origin main
                        fi

                        cd ${APP_DIR}

                        if [ ! -f ${ENV_PATH} ]; then
                            echo "ERROR: .env not found"
                            exit 1
                        fi

                        echo "--- [2] BACKUP IMAGE ---"
                        docker tag ${APP_IMAGE}:latest ${APP_IMAGE}:backup || true
                        docker tag ${GW_IMAGE}:latest  ${GW_IMAGE}:backup  || true

                        echo "--- [3] DEPLOY ---"
                        docker compose --env-file ${ENV_PATH} pull
                        docker compose --env-file ${ENV_PATH} up -d --remove-orphans

                        echo "--- [4] WAIT ---"
                        sleep 25

                        echo "--- [5] HEALTH CHECK ---"
                        STATUS_APP=\$(docker inspect -f "{{.State.Health.Status}}" docapp_django || echo "unhealthy")
                        STATUS_GW=\$(docker inspect -f "{{.State.Running}}" openresty_gateway || echo "false")

                        HTTP_STATUS=\$(curl -k -s -o /dev/null -w "%{http_code}" https://localhost/ || echo "000")

                        echo "APP=\$STATUS_APP GW=\$STATUS_GW HTTP=\$HTTP_STATUS"

                        if [ "\$STATUS_APP" != "healthy" ] || \
                           [ "\$STATUS_GW" != "true" ] || \
                           { [ "\$HTTP_STATUS" != "200" ] && \
                             [ "\$HTTP_STATUS" != "301" ] && \
                             [ "\$HTTP_STATUS" != "302" ]; }; then

                            echo "❌ DEPLOY FAIL → ROLLBACK"

                            docker compose down

                            docker tag ${APP_IMAGE}:backup ${APP_IMAGE}:latest || true
                            docker tag ${GW_IMAGE}:backup  ${GW_IMAGE}:latest  || true

                            docker compose up -d
                            exit 1
                        fi

                        echo "✅ DEPLOY SUCCESS: ${IMAGE_TAG}"

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
    }
}