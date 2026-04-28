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

        DOCKERHUB_CREDS = credentials('dockerhub-creds')
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

                echo "Running Django tests..."

                OUTPUT=$(docker run --rm \
                    --entrypoint "" \
                    -e DEBUG=True \
                    -e SECRET_KEY=test-key \
                    -e JWT_SECRET_KEY=test-jwt \
                    -e DB_ENGINE=django.db.backends.sqlite3 \
                    -e DB_NAME=/tmp/test.db \
                    $APP_IMAGE:$IMAGE_TAG \
                    python manage.py test --verbosity=2 2>&1)

                echo "$OUTPUT"

                echo "$OUTPUT" | grep -q "FAILED"
                if [ $? -eq 0 ]; then
                    echo "TEST FAILED"
                    exit 1
                fi

                echo "TEST PASSED"
                '''
            }
        }

        stage('Push Images') {
            steps {
                sh '''
                echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin

                docker push $APP_IMAGE:$IMAGE_TAG
                docker push $APP_IMAGE:latest

                docker push $GW_IMAGE:$IMAGE_TAG
                docker push $GW_IMAGE:latest
                '''
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

echo "[1] SYNC CODE"
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
    echo "ERROR: Missing .env"
    exit 1
fi

echo "[2] BACKUP IMAGE"
docker image inspect "$APP_IMAGE:latest" >/dev/null 2>&1 && docker tag "$APP_IMAGE:latest" "$APP_IMAGE:backup"
docker image inspect "$GW_IMAGE:latest"  >/dev/null 2>&1 && docker tag "$GW_IMAGE:latest"  "$GW_IMAGE:backup"

echo "[3] DEPLOY NEW VERSION"
$DOCKER_COMPOSE --env-file "$ENV_PATH" pull
$DOCKER_COMPOSE --env-file "$ENV_PATH" up -d --remove-orphans

echo "WAIT 25s..."
sleep 25

echo "[4] HEALTH CHECK"

HTTP_STATUS="000"

for i in {1..10}; do
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 5 \
    --connect-timeout 3 \
    -A "HealthChecker/1.0" \
    -H "Host: dacn3.duckdns.org" \
    -H "X-Forwarded-For: 127.0.0.1" \
    http://127.0.0.1/health/ || echo "000")

    echo "Try $i -> $HTTP_STATUS"

    if [ "$HTTP_STATUS" = "200" ]; then
        break
    fi

    sleep 3
done

APP_STATUS=$(docker inspect -f "{{.State.Health.Status}}" docapp_django 2>/dev/null || echo "unknown")
GW_STATUS=$(docker inspect -f "{{.State.Running}}" openresty_gateway 2>/dev/null || echo "false")

echo "APP=$APP_STATUS | GW=$GW_STATUS | HTTP=$HTTP_STATUS"

if [ "$APP_STATUS" != "healthy" ] || \
   [ "$GW_STATUS" != "true" ] || \
   [ "$HTTP_STATUS" != "200" ]; then

    echo "DEPLOY FAILED -> ROLLBACK"

    $DOCKER_COMPOSE --env-file "$ENV_PATH" down

    docker image inspect "$APP_IMAGE:backup" >/dev/null 2>&1 && \
    docker tag "$APP_IMAGE:backup" "$APP_IMAGE:latest"

    docker image inspect "$GW_IMAGE:backup" >/dev/null 2>&1 && \
    docker tag "$GW_IMAGE:backup" "$GW_IMAGE:latest"

    $DOCKER_COMPOSE --env-file "$ENV_PATH" up -d

    exit 1
fi

echo "DEPLOY SUCCESS"

docker image prune -f
docker container prune -f

rm -f /tmp/deploy_script.sh
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
