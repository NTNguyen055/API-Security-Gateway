// =============================================================================
// Adaptive Web Security Gateway — Jenkinsfile
// =============================================================================

pipeline {
    agent any

    // =========================================================================
    // OPTIONS
    // =========================================================================
    options {
        disableConcurrentBuilds(abortPrevious: true)
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '5'))
        timestamps()
    }

    // =========================================================================
    // ENVIRONMENT
    // =========================================================================
    environment {
        APP_IMAGE = 'ntnguyen055/api-security-app'
        GW_IMAGE  = 'ntnguyen055/api-security-gateway'
        IMAGE_TAG = "v${BUILD_NUMBER}"

        DOCKER_BUILDKIT          = '1'
        COMPOSE_DOCKER_CLI_BUILD = '1'

        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        EC2_SSH_CREDS   = 'app-server-ssh'
        EC2_APP_IP      = '13.159.56.185'
        EC2_USER        = 'ubuntu'

        BASE_DIR        = '/home/ubuntu/appointment-web'
        APP_DIR         = '/home/ubuntu/appointment-web/API-Security-Gateway'
        ENV_PATH        = '/home/ubuntu/appointment-web/.env'

        HEALTH_DOMAIN   = 'dacn3.duckdns.org'
        HEALTH_RETRIES  = '12'
        COMPOSE_TIMEOUT = '120'
    }

    // =========================================================================
    // STAGES
    // =========================================================================
    stages {

        // ── STAGE 1: CHECKOUT ─────────────────────────────────────────────────
        stage('Checkout') {
            steps {
                echo "📥 [1/6] Checking out source code..."
                checkout scm
                sh '''
                    echo "Branch  : $(git rev-parse --abbrev-ref HEAD)"
                    echo "Commit  : $(git rev-parse HEAD)"
                    echo "Message : $(git log -1 --pretty=%s)"
                    echo "Author  : $(git log -1 --pretty=%an)"
                '''
            }
        }

        // ── STAGE 2: LINT & PRE-BUILD CHECKS ──────────────────────────────────
        stage('Lint & Pre-Build Checks') {
            steps {
                echo "🔍 [2/6] Running pre-build checks..."

                sh '''
                    echo "--- Checking required files ---"

                    test -f docappsystem/Dockerfile                || { echo "MISSING: docappsystem/Dockerfile";   exit 1; }
                    test -f docappsystem/requirements.txt           || { echo "MISSING: requirements.txt";          exit 1; }
                    test -f docappsystem/docappsystem/settings.py   || { echo "MISSING: settings.py";               exit 1; }
                    test -f docappsystem/docappsystem/middleware.py || { echo "MISSING: middleware.py";             exit 1; }
                    test -f nginx/Dockerfile                        || { echo "MISSING: nginx/Dockerfile";           exit 1; }
                    test -f nginx/nginx.conf                        || { echo "MISSING: nginx/nginx.conf";           exit 1; }
                    test -f docker-compose.yml                      || { echo "MISSING: docker-compose.yml";        exit 1; }

                    for lua in xff_guard ip_blacklist geo_block bad_bot \
                               rate_limit rate_limit_redis waf_sqli_xss \
                               jwt_auth risk_engine; do
                        test -f "nginx/lua/${lua}.lua" || { echo "MISSING Lua: nginx/lua/${lua}.lua"; exit 1; }
                    done

                    if [ ! -f nginx/GeoLite2-Country.mmdb ]; then
                        echo "WARNING: nginx/GeoLite2-Country.mmdb not found. MaxMindDB lookup will not work correctly."
                    fi

                    echo "All required files present."
                '''
                // Lệnh test nginx.conf đã được dời sang Stage 4 để test trên image thực tế
            }
        }

        // ── STAGE 3: BUILD IMAGES ─────────────────────────────────────────────
        stage('Build Images') {
            steps {
                echo "🏗️  [3/6] Building Docker images..."

                sh '''
                    echo "--- Building Django App ---"
                    docker build \
                        --pull \
                        --cache-from ${APP_IMAGE}:latest \
                        --build-arg BUILDKIT_INLINE_CACHE=1 \
                        -t ${APP_IMAGE}:${IMAGE_TAG} \
                        -t ${APP_IMAGE}:latest \
                        -f docappsystem/Dockerfile \
                        ./docappsystem
                '''

                sh '''
                    echo "--- Building OpenResty Gateway ---"
                    docker build \
                        --pull \
                        --cache-from ${GW_IMAGE}:latest \
                        --build-arg BUILDKIT_INLINE_CACHE=1 \
                        -t ${GW_IMAGE}:${IMAGE_TAG} \
                        -t ${GW_IMAGE}:latest \
                        -f nginx/Dockerfile \
                        ./nginx
                '''
            }
        }

        // ── STAGE 4: SMOKE TEST ───────────────────────────────────────────────
        stage('Smoke Test') {
            steps {
                echo "🧪 [4/6] Running smoke tests..."

                // 1. Test Django
                sh '''
                    docker run --rm \
                        -e SECRET_KEY=smoke-only-not-real -e DEBUG=False \
                        -e ALLOWED_HOSTS=localhost -e DB_NAME=smoke \
                        -e DB_USER=smoke -e DB_PASSWORD=smoke -e DB_HOST=localhost \
                        -e REDIS_URL=redis://localhost:6379/1 \
                        ${APP_IMAGE}:${IMAGE_TAG} \
                        python -c "print('[SMOKE] Django image OK')"
                '''

                // 2. NÂNG CẤP: Test Nginx Syntax trực tiếp trên image vừa build (Chuẩn xác 100%)
                sh '''
                    echo "--- Validating nginx.conf syntax on built image ---"
                    docker run --rm ${GW_IMAGE}:${IMAGE_TAG} /usr/local/openresty/bin/openresty -t
                    echo "[SMOKE] nginx.conf syntax OK"
                '''

                // 3. Test Lua Deps
                sh '''
                    echo "--- Gateway smoke test: Lua deps ---"
                    docker run --rm ${GW_IMAGE}:${IMAGE_TAG} resty -e "
                        local libs = {'resty.jwt', 'resty.http', 'resty.redis', 'resty.sha256', 'resty.string', 'resty.limit.req', 'prometheus'}
                        for _, lib in ipairs(libs) do
                            assert(pcall(require, lib), 'MISSING: ' .. lib)
                        end
                        print('[SMOKE] All Gateway Lua deps OK')
                    "
                '''
            }
        }

        // ── STAGE 5: PUSH TO DOCKERHUB ────────────────────────────────────────
        stage('Push to DockerHub') {
            steps {
                echo "🐳 [5/6] Pushing images to DockerHub..."
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'
                sh '''
                    docker push ${APP_IMAGE}:${IMAGE_TAG}
                    docker push ${APP_IMAGE}:latest
                    docker push ${GW_IMAGE}:${IMAGE_TAG}
                    docker push ${GW_IMAGE}:latest
                '''
            }
        }

        // ── STAGE 6: DEPLOY TO EC2 ────────────────────────────────────────────
        stage('Deploy & Verify') {
            steps {
                echo "🚢 [6/6] Deploying to EC2 (${EC2_APP_IP})..."

                script {
                    def deployScript = '''\
#!/usr/bin/env bash
set -euo pipefail

APP_IMAGE="__APP_IMAGE__"
GW_IMAGE="__GW_IMAGE__"
IMAGE_TAG="__IMAGE_TAG__"
APP_DIR="__APP_DIR__"
BASE_DIR="__BASE_DIR__"
ENV_PATH="__ENV_PATH__"
HEALTH_DOMAIN="__HEALTH_DOMAIN__"
HEALTH_RETRIES="__HEALTH_RETRIES__"
COMPOSE_TIMEOUT="__COMPOSE_TIMEOUT__"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }

log "[1] Validating .env file..."
test -f "${ENV_PATH}" || fail ".env not found at ${ENV_PATH}"

log "[2] Syncing code from GitHub..."
mkdir -p "${BASE_DIR}"
if [ ! -d "${APP_DIR}/.git" ]; then
    git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git "${APP_DIR}"
else
    cd "${APP_DIR}"
    git fetch origin --tags
    git reset --hard origin/main
    git clean -fd
fi
cd "${APP_DIR}"

log "[3] Preparing log directories..."
mkdir -p "${APP_DIR}/logs/nginx" && chmod 755 "${APP_DIR}/logs/nginx"

log "[4] Backing up current images for rollback..."
docker tag "${APP_IMAGE}:latest" "${APP_IMAGE}:rollback" 2>/dev/null || true
docker tag "${GW_IMAGE}:latest"  "${GW_IMAGE}:rollback"  2>/dev/null || true

log "[5] Pulling new images..."
docker pull "${APP_IMAGE}:${IMAGE_TAG}" || fail "Failed to pull APP image"
docker pull "${GW_IMAGE}:${IMAGE_TAG}"  || fail "Failed to pull GW image"
docker tag "${APP_IMAGE}:${IMAGE_TAG}" "${APP_IMAGE}:latest"
docker tag "${GW_IMAGE}:${IMAGE_TAG}"  "${GW_IMAGE}:latest"

do_rollback() {
    log "Initiating rollback..."
    docker compose --env-file "${ENV_PATH}" down --remove-orphans || true
    docker tag "${APP_IMAGE}:rollback" "${APP_IMAGE}:latest" 2>/dev/null || true
    docker tag "${GW_IMAGE}:rollback"  "${GW_IMAGE}:latest"  2>/dev/null || true
    docker compose --env-file "${ENV_PATH}" up -d --wait --wait-timeout "${COMPOSE_TIMEOUT}" --remove-orphans || log "Rollback failed!"
}

log "[6] Deploying via docker compose..."
if ! docker compose --env-file "${ENV_PATH}" up -d --wait --wait-timeout "${COMPOSE_TIMEOUT}" --remove-orphans; then
    do_rollback
    fail "Deployment failed — rolled back"
fi

log "[7] Post-deploy HTTP health check..."
RETRY=0
HTTP_OK=0
while [ "${RETRY}" -lt "${HEALTH_RETRIES}" ]; do
    RETRY=$((RETRY + 1))
    HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" -H "Host: ${HEALTH_DOMAIN}" -H "X-Forwarded-Proto: https" "http://localhost/health/" || echo "000")
    if [ "${HTTP_CODE}" = "200" ]; then
        HTTP_OK=1
        break
    fi
    sleep 10
done

if [ "${HTTP_OK}" -ne 1 ]; then
    do_rollback
    fail "Health check failed — rolled back"
fi

log "[8] Verifying containers..."
for svc in docapp_django docapp_redis openresty_gateway; do
    STATUS=$(docker inspect --format="{{.State.Status}}" "${svc}" 2>/dev/null || echo "missing")
    if [ "${STATUS}" != "running" ]; then
        do_rollback
        fail "Container ${svc} not running"
    fi
done

log "[9] Cleaning up old images..."
docker image prune -f
docker image prune -af --filter "until=48h" 2>/dev/null || true

log "=================================================="
log "DEPLOYMENT SUCCESSFUL"
log "=================================================="
'''
                    deployScript = deployScript
                        .replace('__APP_IMAGE__',      env.APP_IMAGE)
                        .replace('__GW_IMAGE__',       env.GW_IMAGE)
                        .replace('__IMAGE_TAG__',      env.IMAGE_TAG)
                        .replace('__APP_DIR__',        env.APP_DIR)
                        .replace('__BASE_DIR__',       env.BASE_DIR)
                        .replace('__ENV_PATH__',       env.ENV_PATH)
                        .replace('__HEALTH_DOMAIN__',  env.HEALTH_DOMAIN)
                        .replace('__HEALTH_RETRIES__', env.HEALTH_RETRIES)
                        .replace('__COMPOSE_TIMEOUT__',env.COMPOSE_TIMEOUT)

                    writeFile file: 'deploy_remote.sh', text: deployScript
                }

                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh '''
                        scp -o StrictHostKeyChecking=no -o ConnectTimeout=15 deploy_remote.sh ${EC2_USER}@${EC2_APP_IP}:/tmp/deploy_remote_${BUILD_NUMBER}.sh
                        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 ${EC2_USER}@${EC2_APP_IP} "chmod +x /tmp/deploy_remote_${BUILD_NUMBER}.sh && /tmp/deploy_remote_${BUILD_NUMBER}.sh"
                    '''
                }
            }
            post {
                always {
                    sh 'rm -f deploy_remote.sh || true'
                    sshagent(credentials: [EC2_SSH_CREDS]) {
                        sh '''
                            ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_APP_IP} "rm -f /tmp/deploy_remote_${BUILD_NUMBER}.sh" 2>/dev/null || true
                        '''
                    }
                }
            }
        }
    }

    // =========================================================================
    // POST
    // =========================================================================
    post {
        always {
            echo "🧹 Cleaning up Jenkins agent..."
            sh 'docker logout || true'
            sh '''
                docker rmi ${APP_IMAGE}:${IMAGE_TAG} 2>/dev/null || true
                docker rmi ${APP_IMAGE}:latest        2>/dev/null || true
                docker rmi ${GW_IMAGE}:${IMAGE_TAG}  2>/dev/null || true
                docker rmi ${GW_IMAGE}:latest         2>/dev/null || true
                docker image prune -f                2>/dev/null || true
            '''
            
            // FIX: Sử dụng ngoặc kép (""") để Groovy có thể nội suy các biến vào script Bash
            script {
                def result   = currentBuild.currentResult ?: 'UNKNOWN'
                def jobName  = env.JOB_NAME
                def buildNo  = env.BUILD_NUMBER
                def buildUrl = env.BUILD_URL
                sh """
                    echo ""
                    echo "========================================"
                    echo " Build Summary"
                    echo " Job    : ${jobName}"
                    echo " Build  : #${buildNo}"
                    echo " Result : ${result}"
                    echo " URL    : ${buildUrl}"
                    echo "========================================"
                """
            }
        }
        success {
            echo "Pipeline #${BUILD_NUMBER} PASSED — ${APP_IMAGE}:${IMAGE_TAG} deployed"
        }
        failure {
            echo "Pipeline #${BUILD_NUMBER} FAILED — ${BUILD_URL}console"
        }
        unstable {
            echo "Pipeline #${BUILD_NUMBER} UNSTABLE"
        }
    }
}