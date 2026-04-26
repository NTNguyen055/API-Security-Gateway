pipeline {
agent any

options {
    timeout(time: 15, unit: 'MINUTES')
    timestamps()
}

environment {
    APP_IMAGE = 'ntnguyen055/api-security-app'
    GW_IMAGE  = 'ntnguyen055/api-security-gateway'
    IMAGE_TAG = "v${BUILD_NUMBER}"

    DOCKERHUB_CREDS = credentials('dockerhub-creds')
    EC2_SSH_CREDS   = 'app-server-ssh'

    // FIX: chuyển IP sang Jenkins credential thay vì hardcode public trên GitHub.
    // Vào Jenkins → Manage Credentials → thêm "Secret text" với id: ec2-app-ip
    EC2_APP_IP = credentials('ec2-app-ip')
    EC2_USER   = 'ubuntu'
}

stages {

    stage('Checkout') {
        steps {
            checkout scm
        }
    }

    stage('Build Images') {
        steps {
            sh '''
            set -e

            echo "=== BUILD APP IMAGE ==="
            docker build \
                -t $APP_IMAGE:$IMAGE_TAG \
                -t $APP_IMAGE:latest \
                ./docappsystem

            echo "=== BUILD GATEWAY IMAGE ==="
            docker build \
                -t $GW_IMAGE:$IMAGE_TAG \
                -t $GW_IMAGE:latest \
                ./nginx
            '''
        }
    }

    stage('Run Tests') {
        steps {
            sh '''
            set -e

            echo "=== RUN DJANGO TESTS ==="

            docker run --rm \
                --entrypoint "" \
                -e DEBUG=True \
                -e SECRET_KEY=test-key \
                -e JWT_SECRET_KEY=test-jwt \
                -e DB_ENGINE=django.db.backends.sqlite3 \
                -e DB_NAME=/tmp/test.db \
                $APP_IMAGE:$IMAGE_TAG \
                python manage.py test --verbosity=2
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

    stage('Deploy & Rollback') {
        steps {

            writeFile file: '/tmp/deploy_script.sh', text: '''#!/bin/bash

set -e

BASE_DIR="/home/ubuntu/appointment-web"
APP_DIR="/home/ubuntu/appointment-web/API-Security-Gateway"
ENV_PATH="/home/ubuntu/appointment-web/.env"

APP_CONTAINER="docapp_django"
GW_CONTAINER="openresty_gateway"

APP_IMAGE="ntnguyen055/api-security-app"
GW_IMAGE="ntnguyen055/api-security-gateway"

mkdir -p "$BASE_DIR"

echo "===== [1] SYNC CODE ====="

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
    echo "ERROR: .env not found"
    exit 1
fi

echo "===== [2] BACKUP IMAGE ====="
docker tag "$APP_IMAGE:latest" "$APP_IMAGE:backup" 2>/dev/null || true
docker tag "$GW_IMAGE:latest"  "$GW_IMAGE:backup"  2>/dev/null || true

echo "===== [3] DEPLOY ====="
docker compose --env-file "$ENV_PATH" pull
docker compose --env-file "$ENV_PATH" up -d --remove-orphans

echo "Waiting 30s for all containers to be fully ready..."
sleep 30

echo "===== [4] DJANGO INIT (migrate + collectstatic) ====="

docker exec "$APP_CONTAINER" python manage.py migrate --noinput

# collectstatic co the fail nhe khong nen kill deploy
docker exec "$APP_CONTAINER" python manage.py collectstatic --noinput || true

echo "===== [5] HEALTH CHECK ====="

HTTP_STATUS="000"

for i in $(seq 1 15); do
    CURL_OUT=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 8 \
        --connect-timeout 5 \
        -A "HealthChecker/1.0" \
        -H "Host: dacn3.duckdns.org" \
        "http://127.0.0.1/health/" 2>/dev/null) || CURL_OUT="000"

    HTTP_STATUS="$CURL_OUT"
    echo "Attempt $i → HTTP=$HTTP_STATUS"

    if [ "$HTTP_STATUS" = "200" ]; then
        break
    fi

    if [ "$i" = "3" ]; then
        echo "--- Container status ---"
        docker ps --format "table {{.Names}}\t{{.Status}}" || true
        echo "--- Gateway logs (last 20 lines) ---"
        docker logs "$GW_CONTAINER" --tail=20 2>&1 || true
    fi

    sleep 8
done

if [ "$HTTP_STATUS" != "200" ]; then
    echo "DEPLOY FAILED → ROLLBACK"

    docker compose --env-file "$ENV_PATH" down

    docker tag "$APP_IMAGE:backup" "$APP_IMAGE:latest" 2>/dev/null || true
    docker tag "$GW_IMAGE:backup"  "$GW_IMAGE:latest"  2>/dev/null || true

    docker compose --env-file "$ENV_PATH" up -d

    exit 1
fi

echo "DEPLOY SUCCESS"

docker image prune -f
'''

            sshagent(credentials: [EC2_SSH_CREDS]) {
                sh """
                scp -o StrictHostKeyChecking=no \
                    /tmp/deploy_script.sh \
                    ${EC2_USER}@${EC2_APP_IP}:/tmp/deploy_script.sh

                ssh -o StrictHostKeyChecking=no \
                    ${EC2_USER}@${EC2_APP_IP} \
                    'bash /tmp/deploy_script.sh'
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
        echo "Pipeline completed successfully!"
    }

    failure {
        echo "Pipeline failed! Check logs."
    }
}
}
