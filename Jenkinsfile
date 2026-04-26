pipeline {
    agent any

    options {
        timeout(time: 25, unit: 'MINUTES')   // ✅ TĂNG: 20→25 (deploy + health check dài)
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    environment {
        APP_IMAGE = 'ntnguyen055/api-security-app'
        GW_IMAGE  = 'ntnguyen055/api-security-gateway'

        IMAGE_TAG = "v${BUILD_NUMBER}"

        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'

        EC2_APP_IP = '13.159.56.185'
        EC2_USER   = 'ubuntu'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        // ✅ FIX: Chỉ prune dangling images, KHÔNG prune toàn bộ (mất build cache)
        stage('Clean Docker') {
            steps {
                sh '''
                docker image prune -f  || true
                docker builder prune --keep-storage=5g -f || true
                '''
            }
        }

        stage('Build Images') {
            steps {
                sh '''
                set -e
                export DOCKER_BUILDKIT=1

                echo "=== BUILD APP IMAGE ==="
                docker build \
                    --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
                    --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
                    --cache-from $APP_IMAGE:latest \
                    -t $APP_IMAGE:$IMAGE_TAG \
                    -t $APP_IMAGE:latest \
                    ./docappsystem

                echo "=== BUILD GATEWAY IMAGE ==="
                docker build \
                    --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
                    --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
                    --cache-from $GW_IMAGE:latest \
                    -t $GW_IMAGE:$IMAGE_TAG \
                    -t $GW_IMAGE:latest \
                    ./nginx
                '''
            }
        }

        // ✅ THÊM: Security scan trước khi push
        stage('Security Scan') {
            steps {
                sh '''
                set -e

                echo "=== TRIVY SCAN: APP ==="
                docker run --rm \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    aquasec/trivy:latest image \
                    --exit-code 0 \
                    --severity HIGH,CRITICAL \
                    --ignore-unfixed \
                    $APP_IMAGE:$IMAGE_TAG || true

                echo "=== TRIVY SCAN: GATEWAY ==="
                docker run --rm \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    aquasec/trivy:latest image \
                    --exit-code 0 \
                    --severity HIGH,CRITICAL \
                    --ignore-unfixed \
                    $GW_IMAGE:$IMAGE_TAG || true
                '''
            }
        }

        stage('Run Tests') {
            steps {
                sh '''
                set -e

                echo "=== DJANGO CHECK + TEST ==="
                docker run --rm \
                    --entrypoint "" \
                    -e DEBUG=False \
                    -e ALLOWED_HOSTS="*" \
                    -e SECRET_KEY="super_long_dummy_secret_key_for_jenkins_testing_purposes_only_123456789" \
                    -e JWT_SECRET_KEY="super_long_dummy_jwt_key_for_jenkins_testing_purposes_only_987654321" \
                    -e DB_ENGINE=django.db.backends.sqlite3 \
                    -e DB_NAME=/tmp/test.db \
                    $APP_IMAGE:$IMAGE_TAG \
                    sh -c "
                        python manage.py check --deploy &&
                        python manage.py test --verbosity=2
                    "
                '''
            }
        }

        stage('Push Images') {
            steps {
                sh '''
                set -e

                echo "=== LOGIN DOCKERHUB ==="
                echo $DOCKERHUB_CREDS_PSW | docker login \
                    -u $DOCKERHUB_CREDS_USR \
                    --password-stdin

                echo "=== PUSH IMAGES ==="
                docker push $APP_IMAGE:$IMAGE_TAG
                docker push $APP_IMAGE:latest

                docker push $GW_IMAGE:$IMAGE_TAG
                docker push $GW_IMAGE:latest
                '''
            }
        }

        stage('Deploy') {
            steps {
                // ✅ FIX: dùng writeFile với encoding rõ ràng, tránh shell escaping bug
                writeFile file: '/tmp/deploy.sh', text: """#!/bin/bash
set -euo pipefail   # ✅ THÊM: -u (undefined var error) và -o pipefail

BASE_DIR="/home/ubuntu/appointment-web"
APP_DIR="\$BASE_DIR/API-Security-Gateway"
ENV_PATH="\$BASE_DIR/.env"

APP_CONTAINER="docapp_django"
GW_CONTAINER="openresty_gateway"

APP_IMAGE="${APP_IMAGE}"
GW_IMAGE="${GW_IMAGE}"
IMAGE_TAG="${IMAGE_TAG}"

echo "===== [1] PREPARE ====="
mkdir -p "\$BASE_DIR"

if [ ! -d "\$APP_DIR" ]; then
    git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git "\$APP_DIR"
else
    cd "\$APP_DIR"
    git fetch origin
    git reset --hard origin/main
    git clean -fd
fi

cd "\$APP_DIR"

if [ ! -f "\$ENV_PATH" ]; then
    echo "ERROR: .env not found at \$ENV_PATH"
    exit 1
fi

if ! grep -qE "^REDIS_PASSWORD=.+" "\$ENV_PATH"; then
    echo ""
    echo "========================================================="
    echo " ERROR: REDIS_PASSWORD bi thieu hoac khong co trong .env"
    echo "========================================================="
    echo " Them dong nay vao file \$ENV_PATH roi chay lai:"
    echo "   REDIS_PASSWORD=your_strong_password_here"
    echo "========================================================="
    exit 1
fi
echo "Pre-flight OK – REDIS_PASSWORD co trong .env"

echo "===== [2] BACKUP CURRENT VERSION ====="
docker tag \${APP_IMAGE}:latest \${APP_IMAGE}:backup || true
docker tag \${GW_IMAGE}:latest  \${GW_IMAGE}:backup  || true

echo "===== [3] PULL NEW VERSION ====="
docker pull \${APP_IMAGE}:\${IMAGE_TAG}
docker pull \${GW_IMAGE}:\${IMAGE_TAG}

echo "===== [4] DEPLOY ====="
export IMAGE_TAG=\${IMAGE_TAG}
docker compose --env-file "\$ENV_PATH" up -d --remove-orphans

echo "Waiting 30s for containers to stabilise..."
sleep 30

echo "===== [5] MIGRATE + COLLECTSTATIC ====="
docker exec \$APP_CONTAINER python manage.py migrate --noinput
docker exec \$APP_CONTAINER python manage.py collectstatic --noinput || true

echo "===== [6] HEALTH CHECK ====="
HTTP_STATUS="000"

for i in \$(seq 1 20); do
    HTTP_STATUS=\$(curl -k -sf -o /dev/null -w "%{http_code}" \\
        --max-time 5 \\
        https://127.0.0.1/health/ 2>/dev/null || echo "000")

    echo "Attempt \$i → HTTP \$HTTP_STATUS"

    if [ "\$HTTP_STATUS" = "200" ]; then
        break
    fi

    sleep 5
done

if [ "\$HTTP_STATUS" != "200" ]; then
    echo "DEPLOY FAILED → ROLLING BACK"

    docker compose --env-file "\$ENV_PATH" down --remove-orphans

    docker tag \${APP_IMAGE}:backup \${APP_IMAGE}:latest || true
    docker tag \${GW_IMAGE}:backup  \${GW_IMAGE}:latest  || true

    docker compose --env-file "\$ENV_PATH" up -d

    exit 1
fi

echo "===== [7] CLEANUP ====="
docker image prune -f
docker container prune -f   # ✅ THÊM: dọn container stopped

echo "DEPLOY SUCCESS – image tag: \${IMAGE_TAG}"
"""

                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh """
                    scp -o StrictHostKeyChecking=no /tmp/deploy.sh \
                        ${EC2_USER}@${EC2_APP_IP}:/tmp/deploy.sh

                    ssh -o StrictHostKeyChecking=no \
                        -o ConnectTimeout=10 \
                        ${EC2_USER}@${EC2_APP_IP} \
                        'chmod +x /tmp/deploy.sh && bash /tmp/deploy.sh'
                    """
                }
            }
        }
    }

    post {
        always {
            sh '''
            docker logout || true
            docker image prune -f || true
            rm -f /tmp/deploy.sh || true
            '''
            cleanWs()
        }

        success {
            echo "✅ Pipeline SUCCESS – build ${BUILD_NUMBER} deployed"
        }

        failure {
            echo "❌ Pipeline FAILED – build ${BUILD_NUMBER}"
            // ✅ Có thể thêm: emailext / slackSend notification ở đây
        }
    }
}
