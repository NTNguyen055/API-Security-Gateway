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
    }

    stages {

        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Build Images') {
            steps {
                sh '''
                docker builder prune -f

                docker build -t $APP_IMAGE:$IMAGE_TAG \
                             -t $APP_IMAGE:latest \
                             ./docappsystem

                docker build -t $GW_IMAGE:$IMAGE_TAG \
                             -t $GW_IMAGE:latest \
                             ./nginx
                '''
            }
        }

        stage('Test (optional)') {
            steps {
                sh '''
                echo "Running Django tests (optional)..."

                OUTPUT=$(docker run --rm \
                    --entrypoint "" \
                    -e DEBUG=True \
                    -e SECRET_KEY=test-key \
                    -e JWT_SECRET_KEY=test-jwt \
                    -e DB_ENGINE=django.db.backends.sqlite3 \
                    -e DB_NAME=/tmp/test.db \
                    $APP_IMAGE:$IMAGE_TAG \
                    python manage.py test --verbosity=2 2>&1 || true)

                echo "$OUTPUT"

                echo "$OUTPUT" | grep -q "FAILED" && exit 1 || true
                '''
            }
        }

        stage('Push Images') {
            steps {
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                sh '''
                docker push $APP_IMAGE:$IMAGE_TAG
                docker push $APP_IMAGE:latest
                docker push $GW_IMAGE:$IMAGE_TAG
                docker push $GW_IMAGE:latest
                '''
            }
        }

        stage('Deploy & Smart Rollback') {
            steps {
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh """
                    ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} << 'EOF'
                    set -e

                    BASE_DIR="/home/ubuntu/appointment-web"
                    APP_DIR="/home/ubuntu/appointment-web/API-Security-Gateway"
                    ENV_PATH="/home/ubuntu/appointment-web/.env"
                    APP_IMAGE="ntnguyen055/api-security-app"
                    GW_IMAGE="ntnguyen055/api-security-gateway"

                    mkdir -p "\$BASE_DIR"

                    echo "--- [1] SYNC CODE ---"
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
                        echo "ERROR: .env not found"
                        exit 1
                    fi

                    echo "--- [2] BACKUP IMAGE ---"
                    docker tag "\$APP_IMAGE:latest" "\$APP_IMAGE:backup" || true
                    docker tag "\$GW_IMAGE:latest"  "\$GW_IMAGE:backup"  || true

                    echo "--- [3] DEPLOY ---"
                    docker compose --env-file "\$ENV_PATH" pull
                    docker compose --env-file "\$ENV_PATH" up -d --remove-orphans

                    echo "--- WAIT CONTAINERS ---"
                    sleep 10

                    echo "--- [4] HEALTH CHECK ---"

                    STATUS_APP=\$(docker inspect -f "{{.State.Health.Status}}" docapp_django || echo "unhealthy")
                    STATUS_GW=\$(docker inspect -f "{{.State.Running}}" openresty_gateway || echo "false")

                    HTTP_STATUS="000"

                    for i in 1 2 3 4 5 6 7 8 9 10; do
                        HTTP_STATUS=\$(curl -s -o /dev/null -w "%{http_code}" \
                            -H "Host: dacn3.duckdns.org" \
                            http://localhost/health/ || echo "000")

                        echo "Try \$i → HTTP=\$HTTP_STATUS"

                        if [ "\$HTTP_STATUS" = "200" ]; then
                            break
                        fi

                        sleep 3
                    done

                    echo "APP=\$STATUS_APP GW=\$STATUS_GW HTTP=\$HTTP_STATUS"

                    if [ "\$STATUS_APP" != "healthy" ] || \
                       [ "\$STATUS_GW" != "true" ] || \
                       [ "\$HTTP_STATUS" != "200" ]; then

                        echo "❌ DEPLOY FAIL → ROLLBACK"

                        docker compose down

                        docker tag "\$APP_IMAGE:backup" "\$APP_IMAGE:latest" || true
                        docker tag "\$GW_IMAGE:backup"  "\$GW_IMAGE:latest"  || true

                        docker compose up -d
                        exit 1
                    fi

                    echo "✅ DEPLOY SUCCESS: ${IMAGE_TAG}"

                    docker image prune -f
                    EOF
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