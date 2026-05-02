// =============================================================================
// Adaptive Web Security Gateway — Jenkinsfile
// Pipeline: Checkout → Lint → Build → Smoke Test → Push → Deploy → Verify
//
// Images:
//   ntnguyen055/api-security-app     → Django/Gunicorn  (docappsystem/)
//   ntnguyen055/api-security-gateway → OpenResty + Lua  (nginx/)
//
// Target: EC2 ubuntu@13.159.56.185
//   APP_DIR  : /home/ubuntu/appointment-web/API-Security-Gateway
//   ENV_PATH : /home/ubuntu/appointment-web/.env
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

                // --- Kiểm tra file bắt buộc ---
                sh '''
                    echo "--- Checking required files ---"

                    test -f docappsystem/Dockerfile                || { echo "MISSING: docappsystem/Dockerfile";   exit 1; }
                    test -f docappsystem/requirements.txt           || { echo "MISSING: requirements.txt";          exit 1; }
                    test -f docappsystem/docappsystem/settings.py   || { echo "MISSING: settings.py";               exit 1; }
                    test -f docappsystem/docappsystem/middleware.py || { echo "MISSING: middleware.py";              exit 1; }
                    test -f nginx/Dockerfile                        || { echo "MISSING: nginx/Dockerfile";           exit 1; }
                    test -f nginx/nginx.conf                        || { echo "MISSING: nginx/nginx.conf";           exit 1; }
                    test -f docker-compose.yml                      || { echo "MISSING: docker-compose.yml";        exit 1; }

                    for lua in xff_guard ip_blacklist geo_block bad_bot \
                               rate_limit rate_limit_redis waf_sqli_xss \
                               jwt_auth risk_engine; do
                        test -f "nginx/lua/${lua}.lua" || { echo "MISSING Lua: nginx/lua/${lua}.lua"; exit 1; }
                    done

                    if [ ! -f nginx/GeoLite2-Country.mmdb ]; then
                        echo "WARNING: nginx/GeoLite2-Country.mmdb not found."
                        echo "  MaxMindDB lookup will not work correctly."
                        echo "  Download: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
                    fi

                    echo "All required files present."
                '''

                // --- Validate nginx.conf syntax ---
                // Dùng sh '''...''' (single-quote) để tránh Groovy expand $()
                //
                // LƯU Ý: 'host not found in upstream app' là FALSE-POSITIVE
                //   openresty -t chạy container độc lập, không có Docker network
                //   hostname 'app' (docker-compose service) không resolve được
                //   Khi deploy thật: gateway cùng network 'internal' với 'app' -> OK
                //   Chỉ fail khi có lỗi cú pháp thật, bỏ qua lỗi DNS/upstream
                sh '''
                    echo "--- Validating nginx.conf syntax ---"

                    docker run --rm \
                        -v "$(pwd)/nginx/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro" \
                        -v "$(pwd)/nginx/lua:/usr/local/openresty/nginx/lua:ro" \
                        openresty/openresty:alpine-fat \
                        openresty -t > /tmp/nginx_test.log 2>&1 || true

                    REAL_ERRORS=$( (
                        grep -E '\\[(emerg|alert|crit)\\]' /tmp/nginx_test.log \
                        | grep -v 'host not found in upstream' \
                        | grep -v 'no resolver defined'
                    ) || true )

                    if grep -q "successful" /tmp/nginx_test.log; then
                        echo "nginx.conf syntax OK"
                    elif [ -z "$REAL_ERRORS" ]; then
                        echo "nginx.conf syntax OK (DNS warnings ignored)"
                    else
                        echo "nginx.conf syntax FAILED — real config errors:"
                        echo "$REAL_ERRORS"
                        cat /tmp/nginx_test.log
                        exit 1
                    fi
                '''

                // Lua deps check đã được CHUYỂN sang Stage 'Smoke Test'
                // vì resty.jwt, resty.http, prometheus KHÔNG có trong base image
                // mà phải được cài qua luarocks trong nginx/Dockerfile khi build
                // → chỉ có thể verify trên image đã build (GW_IMAGE:IMAGE_TAG)
            }
        }

        // ── STAGE 3: BUILD IMAGES ─────────────────────────────────────────────
        stage('Build Images') {
            steps {
                echo "🏗️  [3/6] Building Docker images..."

                sh '''
                    echo "--- Building Django App ---"
                    docker build \\
                        --pull \\
                        --cache-from ${APP_IMAGE}:latest \\
                        --build-arg BUILDKIT_INLINE_CACHE=1 \\
                        -t ${APP_IMAGE}:${IMAGE_TAG} \\
                        -t ${APP_IMAGE}:latest \\
                        -f docappsystem/Dockerfile \\
                        ./docappsystem
                    echo "Django App built: ${APP_IMAGE}:${IMAGE_TAG}"
                '''

                sh '''
                    echo "--- Building OpenResty Gateway ---"
                    docker build \\
                        --pull \\
                        --cache-from ${GW_IMAGE}:latest \\
                        --build-arg BUILDKIT_INLINE_CACHE=1 \\
                        -t ${GW_IMAGE}:${IMAGE_TAG} \\
                        -t ${GW_IMAGE}:latest \\
                        -f nginx/Dockerfile \\
                        ./nginx
                    echo "Gateway built: ${GW_IMAGE}:${IMAGE_TAG}"
                '''
            }
        }

        // ── STAGE 4: SMOKE TEST ───────────────────────────────────────────────
        stage('Smoke Test') {
            steps {
                echo "🧪 [4/6] Running smoke tests..."

                // Test Django image: chỉ verify container khởi động được
                sh '''
                    docker run --rm \\
                        -e SECRET_KEY=smoke-only-not-real \\
                        -e DEBUG=False \\
                        -e ALLOWED_HOSTS=localhost \\
                        -e DB_NAME=smoke \\
                        -e DB_USER=smoke \\
                        -e DB_PASSWORD=smoke \\
                        -e DB_HOST=localhost \\
                        -e REDIS_URL=redis://localhost:6379/1 \\
                        ${APP_IMAGE}:${IMAGE_TAG} \\
                        python -c "print('[SMOKE] Django image OK')"
                    echo "Django App smoke test passed"
                '''

                // FIX: Lua deps check phải dùng GW_IMAGE đã build (KHÔNG dùng base image)
                // resty.jwt, resty.http, prometheus được cài qua luarocks trong nginx/Dockerfile
                // base image openresty:alpine-fat KHÔNG có sẵn 3 thư viện này
                sh '''
                    echo "--- Gateway smoke test: Lua deps (on built image) ---"
                    docker run --rm \\
                        ${GW_IMAGE}:${IMAGE_TAG} \\
                        resty -e "
                            local results = {}
                            local all_ok = true
                            local libs = {
                                'resty.jwt', 'resty.http', 'resty.redis',
                                'resty.sha256', 'resty.string',
                                'resty.limit.req', 'prometheus'
                            }
                            for _, lib in ipairs(libs) do
                                local ok, err = pcall(require, lib)
                                if ok then
                                    print('OK: ' .. lib)
                                else
                                    print('MISSING: ' .. lib .. ' => ' .. tostring(err))
                                    all_ok = false
                                end
                            end
                            if not all_ok then
                                print('SMOKE FAILED: missing Lua deps in built image')
                                os.exit(1)
                            end
                            print('[SMOKE] All Gateway Lua deps OK')
                        "
                    echo "Gateway smoke test passed"
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
                    echo "All images pushed successfully"
                '''
            }
        }

        // ── STAGE 6: DEPLOY TO EC2 ────────────────────────────────────────────
        //
        // ROOT CAUSE FIX:
        //   Dùng heredoc << 'ENDSSH' bên trong sh'''...''' gây lỗi Groovy parse:
        //   "illegal string body character after dollar sign"
        //   vì Groovy cố expand ký tự sau $ (kể cả số, dấu nháy, ký tự đặc biệt)
        //
        // GIẢI PHÁP: writeFile → tạo bash script trên Jenkins agent → scp → ssh
        //   - Script được viết bằng Groovy string (dễ inject biến Jenkins)
        //   - Bash variable dùng \${VAR} để phân biệt với Groovy ${VAR}
        //   - Không có heredoc, không có conflict quote
        // ─────────────────────────────────────────────────────────────────────
        stage('Deploy & Verify') {
            steps {
                echo "🚢 [6/6] Deploying to EC2 (${EC2_APP_IP})..."

                // Bước 1: Groovy tạo deploy script và ghi ra file
                script {
                    def deployScript = '''\
#!/usr/bin/env bash
set -euo pipefail

# ── INJECT từ Jenkins (Groovy đã thay thế trước khi writeFile) ───────────────
APP_IMAGE="__APP_IMAGE__"
GW_IMAGE="__GW_IMAGE__"
IMAGE_TAG="__IMAGE_TAG__"
APP_DIR="__APP_DIR__"
BASE_DIR="__BASE_DIR__"
ENV_PATH="__ENV_PATH__"
HEALTH_DOMAIN="__HEALTH_DOMAIN__"
HEALTH_RETRIES="__HEALTH_RETRIES__"
COMPOSE_TIMEOUT="__COMPOSE_TIMEOUT__"

# ── HELPERS ───────────────────────────────────────────────────────────────────
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }

# ── [1] VALIDATE .ENV ────────────────────────────────────────────────────────
log "[1] Validating .env file..."
test -f "${ENV_PATH}" || fail ".env not found at ${ENV_PATH}"

for var in SECRET_KEY DB_NAME DB_USER DB_PASSWORD DB_HOST JWT_SECRET_KEY \
           REDIS_URL RATE_LIMIT_RPS RATE_LIMIT_BURST \
           REDIS_RATE_LIMIT REDIS_RL_WINDOW \
           AUTO_BL_THRESHOLD AUTO_BL_WINDOW AUTO_BL_DURATION \
           RISK_BLOCK_THRESHOLD RISK_LIMIT_THRESHOLD ALLOWED_HOSTS; do
    if ! grep -q "^${var}=" "${ENV_PATH}"; then
        echo "  WARNING: ${var} not found in .env"
    fi
done
log "  .env validated"

# ── [2] SYNC CODE ────────────────────────────────────────────────────────────
log "[2] Syncing code from GitHub..."
mkdir -p "${BASE_DIR}"

if [ ! -d "${APP_DIR}/.git" ]; then
    log "  Fresh clone..."
    git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git "${APP_DIR}"
else
    log "  Updating existing repo..."
    cd "${APP_DIR}"
    git fetch origin --tags
    git reset --hard origin/main
    git clean -fd
fi

cd "${APP_DIR}"
log "  Commit: $(git rev-parse --short HEAD)"

# ── [3] LOG DIRS ─────────────────────────────────────────────────────────────
log "[3] Preparing log directories..."
mkdir -p "${APP_DIR}/logs/nginx"
chmod 755 "${APP_DIR}/logs/nginx"

# ── [4] BACKUP CURRENT IMAGES ────────────────────────────────────────────────
log "[4] Backing up current images for rollback..."
docker tag "${APP_IMAGE}:latest" "${APP_IMAGE}:rollback" 2>/dev/null || true
docker tag "${GW_IMAGE}:latest"  "${GW_IMAGE}:rollback"  2>/dev/null || true

# ── [5] PULL NEW IMAGES ──────────────────────────────────────────────────────
log "[5] Pulling new images (tag=${IMAGE_TAG})..."
docker pull "${APP_IMAGE}:${IMAGE_TAG}" || fail "Failed to pull ${APP_IMAGE}:${IMAGE_TAG}"
docker pull "${GW_IMAGE}:${IMAGE_TAG}"  || fail "Failed to pull ${GW_IMAGE}:${IMAGE_TAG}"

docker tag "${APP_IMAGE}:${IMAGE_TAG}" "${APP_IMAGE}:latest"
docker tag "${GW_IMAGE}:${IMAGE_TAG}"  "${GW_IMAGE}:latest"
log "  Images pulled and tagged :latest"

# ── [6] ROLLBACK FUNCTION ────────────────────────────────────────────────────
do_rollback() {
    log "  Initiating rollback..."
    docker compose --env-file "${ENV_PATH}" down --remove-orphans || true
    docker tag "${APP_IMAGE}:rollback" "${APP_IMAGE}:latest" 2>/dev/null || true
    docker tag "${GW_IMAGE}:rollback"  "${GW_IMAGE}:latest"  2>/dev/null || true

    if docker compose --env-file "${ENV_PATH}" up -d \
            --wait --wait-timeout "${COMPOSE_TIMEOUT}" \
            --remove-orphans 2>/dev/null; then
        log "  Rollback succeeded"
    else
        log "  WARNING: Rollback also failed — manual intervention required!"
    fi
}

# ── [7] DEPLOY ───────────────────────────────────────────────────────────────
log "[6] Deploying via docker compose..."
if ! docker compose --env-file "${ENV_PATH}" up -d \
        --wait --wait-timeout "${COMPOSE_TIMEOUT}" \
        --remove-orphans; then
    log "  docker compose failed or timed out"
    do_rollback
    fail "Deployment failed — rolled back"
fi
log "  All containers healthy"

# ── [8] HTTP HEALTH CHECK ────────────────────────────────────────────────────
log "[7] Post-deploy HTTP health check..."
RETRY=0
HTTP_OK=0

while [ "${RETRY}" -lt "${HEALTH_RETRIES}" ]; do
    RETRY=$((RETRY + 1))
    log "  Attempt ${RETRY}/${HEALTH_RETRIES}..."

    HTTP_CODE=$(curl -sf \
        --max-time 5 \
        -o /tmp/health_resp.json \
        -w "%{http_code}" \
        -H "Host: ${HEALTH_DOMAIN}" \
        -H "X-Forwarded-Proto: https" \
        -H "X-Forwarded-For: 127.0.0.1" \
        -A "JenkinsHealthChecker/1.0" \
        "http://localhost/health/" 2>/dev/null || echo "000")

    if [ "${HTTP_CODE}" = "200" ]; then
        RESP=$(cat /tmp/health_resp.json 2>/dev/null || echo "")
        log "  HTTP 200 — ${RESP}"
        if echo "${RESP}" | grep -q '"db": "ok"'; then
            log "  DB check passed"
        else
            log "  WARNING: DB status not ok in health response"
        fi
        HTTP_OK=1
        break
    fi

    log "  HTTP ${HTTP_CODE} — retrying in 10s..."
    sleep 10
done

if [ "${HTTP_OK}" -ne 1 ]; then
    log "  Health check FAILED after ${HEALTH_RETRIES} attempts"
    do_rollback
    fail "Health check failed — deployment rolled back"
fi

# ── [9] VERIFY CONTAINERS ────────────────────────────────────────────────────
log "[8] Verifying containers..."
docker compose --env-file "${ENV_PATH}" ps

for svc in docapp_django docapp_redis openresty_gateway; do
    STATUS=$(docker inspect --format="{{.State.Status}}" "${svc}" 2>/dev/null || echo "missing")
    HEALTH=$(docker inspect --format="{{.State.Health.Status}}" "${svc}" 2>/dev/null || echo "none")
    log "  ${svc}: status=${STATUS} health=${HEALTH}"

    if [ "${STATUS}" != "running" ]; then
        log "  ERROR: ${svc} not running"
        docker logs "${svc}" --tail 30 2>/dev/null || true
        do_rollback
        fail "Container ${svc} not running after deploy"
    fi
done

# ── [10] CLEANUP ─────────────────────────────────────────────────────────────
log "[9] Cleaning up old images..."
docker image prune -f
docker image prune -af --filter "until=48h" 2>/dev/null || true

log ""
log "=================================================="
log "  DEPLOYMENT SUCCESSFUL"
log "  Tag    : ${IMAGE_TAG}"
log "  Domain : https://${HEALTH_DOMAIN}"
log "  Time   : $(date '+%Y-%m-%d %H:%M:%S %Z')"
log "=================================================="
'''
                    // Thay placeholder bằng giá trị Jenkins env thực
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
                    echo "Deploy script written to deploy_remote.sh"
                }

                // Bước 2: SCP lên EC2 rồi chạy
                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh '''
                        echo "--- Uploading deploy script ---"
                        scp -o StrictHostKeyChecking=no \\
                            -o ConnectTimeout=15 \\
                            deploy_remote.sh \\
                            ${EC2_USER}@${EC2_APP_IP}:/tmp/deploy_remote_${BUILD_NUMBER}.sh

                        echo "--- Running deploy script on EC2 ---"
                        ssh -o StrictHostKeyChecking=no \\
                            -o ConnectTimeout=15 \\
                            -o ServerAliveInterval=10 \\
                            ${EC2_USER}@${EC2_APP_IP} \\
                            "chmod +x /tmp/deploy_remote_${BUILD_NUMBER}.sh && /tmp/deploy_remote_${BUILD_NUMBER}.sh"
                    '''
                }
            }

            post {
                always {
                    // Xóa script tạm trên Jenkins agent
                    sh 'rm -f deploy_remote.sh || true'
                    // Xóa script tạm trên EC2
                    sshagent(credentials: [EC2_SSH_CREDS]) {
                        sh '''
                            ssh -o StrictHostKeyChecking=no \\
                                ${EC2_USER}@${EC2_APP_IP} \\
                                "rm -f /tmp/deploy_remote_${BUILD_NUMBER}.sh" 2>/dev/null || true
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
                docker image prune -f                 2>/dev/null || true
            '''
            // FIX: currentBuild.currentResult là Groovy variable
            // KHÔNG đặt trong sh '''...''' vì single-quote không expand Groovy
            // → dùng script{} block, extract ra biến Groovy trước
            script {
                def result   = currentBuild.currentResult ?: 'UNKNOWN'
                def jobName  = env.JOB_NAME
                def buildNo  = env.BUILD_NUMBER
                def buildUrl = env.BUILD_URL
                sh '''
                    echo ""
                    echo "========================================"
                    echo " Build Summary"
                    echo " Job    : ${jobName}"
                    echo " Build  : #${buildNo}"
                    echo " Result : ${result}"
                    echo " URL    : ${buildUrl}"
                    echo "========================================"
                '''
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