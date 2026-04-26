pipeline {
agent any

```
options {
    timeout(time: 20, unit: 'MINUTES')
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

    stage('Build Images') {
        steps {
            sh '''
            set -e

            echo "=== BUILD APP IMAGE ==="
            docker build \
                --cache-from $APP_IMAGE:latest \
                -t $APP_IMAGE:$IMAGE_TAG \
                -t $APP_IMAGE:latest \
                ./docappsystem

            echo "=== BUILD GATEWAY IMAGE ==="
            docker build \
                --cache-from $GW_IMAGE:latest \
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

            echo "=== RUN DJANGO CHECK + TEST ==="

            docker run --rm \
                --entrypoint "" \
                -e DEBUG=True \
                -e SECRET_KEY=test-key \
                -e JWT_SECRET_KEY=test-jwt \
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

            writeFile file: '/tmp/deploy.sh', text: """#!/bin/bash
```

set -e

BASE_DIR="/home/ubuntu/appointment-web"
APP_DIR="$BASE_DIR/API-Security-Gateway"
ENV_PATH="$BASE_DIR/.env"

APP_CONTAINER="docapp_django"
GW_CONTAINER="openresty_gateway"

APP_IMAGE="$APP_IMAGE"
GW_IMAGE="$GW_IMAGE"

IMAGE_TAG="$IMAGE_TAG"

echo "===== [1] PREPARE ====="
mkdir -p "$BASE_DIR"

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

echo "===== [2] BACKUP CURRENT VERSION ====="
docker tag $APP_IMAGE:latest $APP_IMAGE:backup || true
docker tag $GW_IMAGE:latest  $GW_IMAGE:backup  || true

echo "===== [3] PULL NEW VERSION ====="
docker pull $APP_IMAGE:$IMAGE_TAG
docker pull $GW_IMAGE:$IMAGE_TAG

echo "===== [4] DEPLOY ====="
export IMAGE_TAG=$IMAGE_TAG

docker compose --env-file "$ENV_PATH" up -d --remove-orphans

echo "Waiting 25s..."
sleep 25

echo "===== [5] DJANGO MIGRATE ====="
docker exec $APP_CONTAINER python manage.py migrate --noinput

docker exec $APP_CONTAINER python manage.py collectstatic --noinput || true

echo "===== [6] HEALTH CHECK ====="

HTTP_STATUS="000"

for i in $(seq 1 15); do
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
--max-time 5 \
https://127.0.0.1/health/ || echo "000")

```
echo "Attempt \$i → \$HTTP_STATUS"

if [ "\$HTTP_STATUS" = "200" ]; then
    break
fi

sleep 5
```

done

if [ "$HTTP_STATUS" != "200" ]; then
echo "DEPLOY FAILED → ROLLBACK"

```
docker compose --env-file "\$ENV_PATH" down

docker tag \$APP_IMAGE:backup \$APP_IMAGE:latest || true
docker tag \$GW_IMAGE:backup  \$GW_IMAGE:latest || true

docker compose --env-file "\$ENV_PATH" up -d

exit 1
```

fi

echo "DEPLOY SUCCESS"

docker image prune -f
"""

```
            sshagent(credentials: [EC2_SSH_CREDS]) {
                sh """
                scp -o StrictHostKeyChecking=no /tmp/deploy.sh \
                    ${EC2_USER}@${EC2_APP_IP}:/tmp/deploy.sh

                ssh -o StrictHostKeyChecking=no \
                    ${EC2_USER}@${EC2_APP_IP} \
                    'bash /tmp/deploy.sh'
                """
            }
        }
    }
}

post {
    always {
        sh '''
        docker logout || true
        docker system prune -f || true
        '''
        cleanWs()
    }

    success {
        echo "✅ Pipeline SUCCESS"
    }

    failure {
        echo "❌ Pipeline FAILED"
    }
}
```

}
