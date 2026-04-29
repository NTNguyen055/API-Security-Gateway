pipeline {

    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        APP_IMAGE = 'ntnguyen055/api-security-app'
        GW_IMAGE  = 'ntnguyen055/api-security-gateway'
        IMAGE_TAG = "v${BUILD_NUMBER}"

        EC2_SSH_CREDS   = 'app-server-ssh'
        EC2_APP_IP      = '13.159.56.185'
        EC2_USER        = 'ubuntu'
    }

    stages {

        stage('Checkout') {
            steps {
                cleanWs()
                checkout scm
            }
        }

        stage('Build Images') {
            steps {
                sh '''
                set -e

                docker build \
                    -t $APP_IMAGE:$IMAGE_TAG \
                    -t $APP_IMAGE:latest \
                    ./docappsystem

                docker build \
                    -t $GW_IMAGE:$IMAGE_TAG \
                    -t $GW_IMAGE:latest \
                    ./nginx
                '''
            }
        }

        stage('Test (Safe Fail)') {
            steps {
                sh '''
                set +e

                echo "Running Django syntax and configuration check..."

                # Cấp phát các biến môi trường ảo (Mock) để vượt qua vòng validate của settings.py
                OUTPUT=$(docker run --rm \
                    --entrypoint "" \
                    -e DEBUG=True \
                    -e SECRET_KEY=test-key-safefail-123 \
                    -e ALLOWED_HOSTS="*" \
                    -e DB_NAME=test_db \
                    -e DB_USER=test_user \
                    -e DB_PASSWORD=test_pass \
                    -e DB_HOST=localhost \
                    $APP_IMAGE:$IMAGE_TAG \
                    python manage.py check --verbosity=2 2>&1)

                echo "$OUTPUT"

                # Lệnh check sẽ ném ra chữ 'SystemCheckError' hoặc 'Exception' nếu code lỗi
                echo "$OUTPUT" | grep -qEi "SystemCheckError|Exception|Error"
                if [ $? -eq 0 ]; then
                    echo "TEST FAILED: Code có lỗi cấu trúc hoặc cú pháp."
                    exit 1
                fi

                echo "TEST PASSED: Cấu trúc Django hợp lệ."
                '''
            }
        }

        stage('Push Images') {
            steps {
                // Sử dụng withCredentials để giải mã username và password an toàn
                withCredentials([usernamePassword(credentialsId: 'dockerhub-creds', passwordVariable: 'DOCKER_PSW', usernameVariable: 'DOCKER_USR')]) {
                    sh '''
                    echo $DOCKER_PSW | docker login -u $DOCKER_USR --password-stdin

                    docker push $APP_IMAGE:$IMAGE_TAG
                    docker push $APP_IMAGE:latest

                    docker push $GW_IMAGE:$IMAGE_TAG
                    docker push $GW_IMAGE:latest
                    '''
                }
            }
        }

        stage('Deploy & Smart Rollback') {
            steps {

                writeFile file: '/tmp/deploy_script.sh', text: '''#!/bin/bash

set -euo pipefail

BASE_DIR="/home/ubuntu/appointment-web"
APP_DIR="$BASE_DIR/API-Security-Gateway"
ENV_PATH="$BASE_DIR/.env"

APP_IMAGE="ntnguyen055/api-security-app"
GW_IMAGE="ntnguyen055/api-security-gateway"

DOCKER_COMPOSE="docker compose"
if ! $DOCKER_COMPOSE version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
fi

echo "=== DEPLOY START ==="

mkdir -p "$BASE_DIR"

echo "[1] BACKUP CURRENT COMPOSE FILE"
if [ -f "$APP_DIR/docker-compose.yml" ]; then
    cp "$APP_DIR/docker-compose.yml" "/tmp/docker-compose.yml.bak"
fi

echo "[2] SYNC CODE"
if [ ! -d "$APP_DIR" ]; then
    git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git "$APP_DIR"
else
    cd "$APP_DIR"
    git fetch origin
    git reset --hard origin/main
    git clean -fd
fi

cd "$APP_DIR"

if [ ! -f "$ENV_PATH" ]; then
    echo "ERROR: Missing .env file. Please create it manually on the server."
    exit 1
fi

echo "[3] BACKUP IMAGES"
docker image inspect "$APP_IMAGE:latest" >/dev/null 2>&1 && docker tag "$APP_IMAGE:latest" "$APP_IMAGE:backup"
docker image inspect "$GW_IMAGE:latest"  >/dev/null 2>&1 && docker tag "$GW_IMAGE:latest"  "$GW_IMAGE:backup"

echo "[4] DEPLOY NEW VERSION"
$DOCKER_COMPOSE --env-file "$ENV_PATH" pull
$DOCKER_COMPOSE --env-file "$ENV_PATH" up -d --remove-orphans

echo "WAIT 25s FOR CONTAINERS TO SPIN UP..."
sleep 25

echo "[5] HEALTH CHECK"

HTTP_STATUS="000"

for i in {1..10}; do
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 5 \
    --connect-timeout 3 \
    -A "HealthChecker/1.0" \
    -H "Host: dacn3.duckdns.org" \
    -H "X-Forwarded-For: 127.0.0.1" \
    http://127.0.0.1/health/ || echo "000")

    echo "Try $i -> HTTP Status: $HTTP_STATUS"

    if [ "$HTTP_STATUS" = "200" ]; then
        break
    fi

    sleep 3
done

APP_STATUS=$(docker inspect -f "{{.State.Health.Status}}" docapp_django 2>/dev/null || echo "unknown")
GW_STATUS=$(docker inspect -f "{{.State.Running}}" openresty_gateway 2>/dev/null || echo "false")

echo "VERDICT: APP=$APP_STATUS | GW=$GW_STATUS | HTTP=$HTTP_STATUS"

if [ "$APP_STATUS" != "healthy" ] || \
   [ "$GW_STATUS" != "true" ] || \
   [ "$HTTP_STATUS" != "200" ]; then

    echo "❌ DEPLOY FAILED -> INITIATING ROLLBACK..."

    $DOCKER_COMPOSE --env-file "$ENV_PATH" down

    # Khôi phục file compose cũ (tránh rủi ro file mới bị lỗi schema)
    if [ -f "/tmp/docker-compose.yml.bak" ]; then
        cp "/tmp/docker-compose.yml.bak" "$APP_DIR/docker-compose.yml"
    fi

    docker image inspect "$APP_IMAGE:backup" >/dev/null 2>&1 && \
    docker tag "$APP_IMAGE:backup" "$APP_IMAGE:latest"

    docker image inspect "$GW_IMAGE:backup" >/dev/null 2>&1 && \
    docker tag "$GW_IMAGE:backup" "$GW_IMAGE:latest"

    $DOCKER_COMPOSE --env-file "$ENV_PATH" up -d

    exit 1
fi

echo "✅ DEPLOY SUCCESS"

# Cleanup
docker image prune -f
docker container prune -f
rm -f /tmp/deploy_script.sh
rm -f /tmp/docker-compose.yml.bak
'''

                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh """
                    scp -o StrictHostKeyChecking=no /tmp/deploy_script.sh ${EC2_USER}@${EC2_APP_IP}:/tmp/deploy_script.sh
                    ssh -o StrictHostKeyChecking=no -T ${EC2_USER}@${EC2_APP_IP} 'bash /tmp/deploy_script.sh'
                    """
                }
            }
        }
    }

    post {
        always {
            sh 'docker logout || true'
        }
        failure {
            echo "❌ PIPELINE FAILED"
        }
        success {
            echo "✅ DEPLOY SUCCESSFUL"
        }
    }

}