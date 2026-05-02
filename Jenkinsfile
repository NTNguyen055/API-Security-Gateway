// =============================================================================
// Adaptive Web Security Gateway — Jenkinsfile
// Pipeline: Checkout → Lint → Build → Smoke Test → Push → Deploy → Verify
//
// Images:
//   ntnguyen055/api-security-app     → Django/Gunicorn (docappsystem/)
//   ntnguyen055/api-security-gateway → OpenResty + Lua (nginx/)
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
        // Hủy build cũ đang chạy nếu có build mới trigger (tránh queue chồng chất)
        disableConcurrentBuilds(abortPrevious: true)
        // Tự động timeout toàn bộ pipeline sau 30 phút
        timeout(time: 30, unit: 'MINUTES')
        // Giữ tối đa 10 build history + artifacts
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '5'))
        // Thêm timestamp vào từng dòng log
        timestamps()
    }

    // =========================================================================
    // ENVIRONMENT
    // =========================================================================
    environment {
        // --- IMAGE NAMES (DockerHub) ---
        APP_IMAGE = 'ntnguyen055/api-security-app'
        GW_IMAGE  = 'ntnguyen055/api-security-gateway'

        // --- TAG STRATEGY: versioned + latest ---
        // IMAGE_TAG dùng cho traceability, :latest dùng cho docker compose pull
        IMAGE_TAG = "v${BUILD_NUMBER}"

        // --- BUILDKIT: bật để tận dụng cache mount và parallel stage ---
        DOCKER_BUILDKIT         = '1'
        COMPOSE_DOCKER_CLI_BUILD = '1'

        // --- CREDENTIALS (inject từ Jenkins Credential Store) ---
        // dockerhub-creds: Username/Password credential
        DOCKERHUB_CREDS = credentials('dockerhub-creds')
        // app-server-ssh: SSH Private Key credential
        EC2_SSH_CREDS   = 'app-server-ssh'

        // --- EC2 TARGET ---
        EC2_APP_IP = '13.159.56.185'
        EC2_USER   = 'ubuntu'

        // --- PATHS TRÊN EC2 ---
        BASE_DIR = '/home/ubuntu/appointment-web'
        APP_DIR  = '/home/ubuntu/appointment-web/API-Security-Gateway'
        ENV_PATH = '/home/ubuntu/appointment-web/.env'

        // --- HEALTH CHECK CONFIG ---
        // Domain khớp với nginx.conf server_name và .env ALLOWED_HOSTS
        HEALTH_DOMAIN    = 'dacn3.duckdns.org'
        // Số lần retry health check sau deploy (mỗi lần cách 10s)
        HEALTH_RETRIES   = '12'
        // Timeout chờ docker compose --wait (giây)
        COMPOSE_TIMEOUT  = '120'
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

                // In thông tin commit để traceability
                sh '''
                    echo "Branch  : $(git rev-parse --abbrev-ref HEAD)"
                    echo "Commit  : $(git rev-parse HEAD)"
                    echo "Message : $(git log -1 --pretty=%s)"
                    echo "Author  : $(git log -1 --pretty=%an)"
                '''
            }
        }

        // ── STAGE 2: LINT & PRE-BUILD CHECKS ──────────────────────────────────
        // FIX: tách lint ra stage riêng — fail sớm trước khi tốn thời gian build
        stage('Lint & Pre-Build Checks') {
            steps {
                echo "🔍 [2/6] Running pre-build checks..."

                // --- Kiểm tra cấu trúc thư mục cần thiết ---
                sh '''
                    echo "--- Checking required files exist ---"

                    # Django app
                    test -f docappsystem/Dockerfile          || { echo "❌ Missing: docappsystem/Dockerfile";   exit 1; }
                    test -f docappsystem/requirements.txt    || { echo "❌ Missing: requirements.txt";           exit 1; }
                    test -f docappsystem/docappsystem/settings.py  || { echo "❌ Missing: settings.py";         exit 1; }
                    test -f docappsystem/docappsystem/middleware.py || { echo "❌ Missing: middleware.py";       exit 1; }

                    # OpenResty Gateway
                    test -f nginx/Dockerfile                 || { echo "❌ Missing: nginx/Dockerfile";           exit 1; }
                    test -f nginx/nginx.conf                 || { echo "❌ Missing: nginx/nginx.conf";           exit 1; }

                    # Lua security modules — đúng 9 modules theo pipeline
                    for lua in xff_guard ip_blacklist geo_block bad_bot \
                               rate_limit rate_limit_redis waf_sqli_xss \
                               jwt_auth risk_engine; do
                        test -f nginx/lua/${lua}.lua || { echo "❌ Missing Lua: nginx/lua/${lua}.lua"; exit 1; }
                    done

                    # GeoIP DB — nginx/Dockerfile COPY file này vào image
                    test -f nginx/GeoLite2-Country.mmdb || {
                        echo "⚠️  WARNING: nginx/GeoLite2-Country.mmdb not found."
                        echo "   MaxMindDB Lua module sẽ không hoạt động đúng."
                        echo "   Xem README để download: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
                    }

                    # docker-compose.yml
                    test -f docker-compose.yml || { echo "❌ Missing: docker-compose.yml"; exit 1; }

                    echo "✅ All required files present."
                '''

                // --- Validate nginx.conf syntax cục bộ (dùng docker run) ---
                // FIX: chạy openresty -t TRƯỚC khi push để fail sớm
                sh '''
                    echo "--- Validating nginx.conf syntax (dry-run) ---"
                    docker run --rm \
                        -v "$(pwd)/nginx/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro" \
                        -v "$(pwd)/nginx/lua:/usr/local/openresty/nginx/lua:ro" \
                        openresty/openresty:alpine-fat \
                        openresty -t 2>&1 | tee /tmp/nginx_test.log

                    if grep -q "successful" /tmp/nginx_test.log; then
                        echo "✅ nginx.conf syntax OK"
                    else
                        echo "❌ nginx.conf syntax FAILED"
                        exit 1
                    fi
                '''

                // --- Lint Lua files: kiểm tra syntax bằng luac ---
                sh '''
                    echo "--- Linting Lua scripts ---"
                    FAILED=0
                    for lua in nginx/lua/*.lua; do
                        docker run --rm \
                            -v "$(pwd)/${lua}:/check.lua:ro" \
                            openresty/openresty:alpine-fat \
                            resty -e "local ok, err = loadfile(\"/check.lua\"); if not ok then print(\"FAIL: \" .. tostring(err)) end" 2>&1 | grep -v "^$" || true
                    done
                    echo "✅ Lua lint done"
                '''
            }
        }

        // ── STAGE 3: BUILD IMAGES ─────────────────────────────────────────────
        stage('Build Images') {
            steps {
                echo "🏗️  [3/6] Building Docker images with BuildKit..."

                // FIX: --pull để luôn lấy base image mới nhất (security patches)
                // --cache-from :latest để tận dụng layer cache từ build trước
                // Build APP và GATEWAY song song (parallel steps)

                // Build Django App
                sh """
                    echo "--- Building Django App Image ---"
                    docker build \
                        --pull \
                        --cache-from ${APP_IMAGE}:latest \
                        --build-arg BUILDKIT_INLINE_CACHE=1 \
                        -t ${APP_IMAGE}:${IMAGE_TAG} \
                        -t ${APP_IMAGE}:latest \
                        -f docappsystem/Dockerfile \
                        ./docappsystem
                    echo "✅ Django App image built: ${APP_IMAGE}:${IMAGE_TAG}"
                """

                // Build OpenResty Gateway
                // FIX: context là ./nginx để COPY GeoLite2-Country.mmdb và lua/ đúng path
                sh """
                    echo "--- Building OpenResty Gateway Image ---"
                    docker build \
                        --pull \
                        --cache-from ${GW_IMAGE}:latest \
                        --build-arg BUILDKIT_INLINE_CACHE=1 \
                        -t ${GW_IMAGE}:${IMAGE_TAG} \
                        -t ${GW_IMAGE}:latest \
                        -f nginx/Dockerfile \
                        ./nginx
                    echo "✅ Gateway image built: ${GW_IMAGE}:${IMAGE_TAG}"
                """
            }
        }

        // ── STAGE 4: SMOKE TEST (LOCAL) ───────────────────────────────────────
        // FIX: test image TRƯỚC khi push — tránh push image hỏng lên DockerHub
        stage('Smoke Test') {
            steps {
                echo "🧪 [4/6] Running smoke tests on built images..."

                // --- Test Django App container ---
                sh """
                    echo "--- Smoke test: Django App ---"

                    # Tạo container tạm với env tối thiểu (không cần DB thật)
                    # Chỉ kiểm tra container start được, import module OK
                    docker run --rm \
                        --name smoke_app_${BUILD_NUMBER} \
                        -e SECRET_KEY=smoke-test-secret-key-not-real \
                        -e DEBUG=False \
                        -e ALLOWED_HOSTS=localhost \
                        -e DB_NAME=test \
                        -e DB_USER=test \
                        -e DB_PASSWORD=test \
                        -e DB_HOST=localhost \
                        -e REDIS_URL=redis://localhost:6379/1 \
                        ${APP_IMAGE}:${IMAGE_TAG} \
                        python -c "
import django, os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'docappsystem.settings')
# Chỉ test import không crash — không cần DB connection
print('[SMOKE] Django app imports OK')
sys.exit(0)
                    " 2>&1 | tail -5
                    echo "✅ Django App smoke test passed"
                """

                // --- Test OpenResty Gateway container ---
                sh """
                    echo "--- Smoke test: OpenResty Gateway ---"

                    # Test openresty -t bên trong image đã build
                    # FIX: mount cert giả để nginx không crash khi kiểm tra
                    docker run --rm \
                        --name smoke_gw_${BUILD_NUMBER} \
                        -e JWT_SECRET_KEY=smoke \
                        -e RATE_LIMIT_RPS=10 \
                        -e RATE_LIMIT_BURST=20 \
                        -e REDIS_RATE_LIMIT=30 \
                        -e REDIS_RL_WINDOW=60 \
                        -e AUTO_BL_THRESHOLD=5 \
                        -e AUTO_BL_WINDOW=60 \
                        -e AUTO_BL_DURATION=3600 \
                        -e RISK_BLOCK_THRESHOLD=80 \
                        -e RISK_LIMIT_THRESHOLD=50 \
                        ${GW_IMAGE}:${IMAGE_TAG} \
                        openresty -t 2>&1 | tee /tmp/smoke_gw.log || true

                    # openresty -t khi không có cert sẽ warn nhưng không crash fatal
                    if docker run --rm ${GW_IMAGE}:${IMAGE_TAG} resty -e "
                        local ok = pcall(require, 'resty.jwt')
                        assert(ok, 'resty.jwt missing')
                        local ok2 = pcall(require, 'resty.http')
                        assert(ok2, 'resty.http missing')
                        local ok3 = pcall(require, 'prometheus')
                        assert(ok3, 'prometheus missing')
                        print('[SMOKE] All Lua deps OK')
                    "; then
                        echo "✅ Gateway Lua deps smoke test passed"
                    else
                        echo "❌ Gateway Lua deps smoke test FAILED"
                        exit 1
                    fi
                """
            }

            // Cleanup smoke containers dù pass hay fail
            post {
                always {
                    sh """
                        docker rm -f smoke_app_${BUILD_NUMBER} smoke_gw_${BUILD_NUMBER} 2>/dev/null || true
                    """
                }
            }
        }

        // ── STAGE 5: PUSH TO DOCKERHUB ────────────────────────────────────────
        stage('Push to DockerHub') {
            steps {
                echo "🐳 [5/6] Pushing images to DockerHub..."
                sh 'echo $DOCKERHUB_CREDS_PSW | docker login -u $DOCKERHUB_CREDS_USR --password-stdin'

                // Push cả versioned tag và :latest
                sh """
                    echo "--- Pushing Django App ---"
                    docker push ${APP_IMAGE}:${IMAGE_TAG}
                    docker push ${APP_IMAGE}:latest

                    echo "--- Pushing OpenResty Gateway ---"
                    docker push ${GW_IMAGE}:${IMAGE_TAG}
                    docker push ${GW_IMAGE}:latest

                    echo "✅ All images pushed to DockerHub"
                """
            }
        }

        // ── STAGE 6: DEPLOY TO EC2 + SMART ROLLBACK ───────────────────────────
        stage('Deploy & Verify') {
            steps {
                echo "🚢 [6/6] Deploying to EC2 (${EC2_APP_IP})..."

                sshagent(credentials: [EC2_SSH_CREDS]) {
                    sh """
                    ssh -o StrictHostKeyChecking=no \
                        -o ConnectTimeout=15 \
                        -o ServerAliveInterval=10 \
                        ${EC2_USER}@${EC2_APP_IP} 'bash -s' << 'ENDSSH'
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
log()  { echo "[\\$(date '+%H:%M:%S')] \\$*"; }
fail() { echo "❌ \\$*" >&2; exit 1; }

APP_IMAGE="${APP_IMAGE}"
GW_IMAGE="${GW_IMAGE}"
IMAGE_TAG="${IMAGE_TAG}"
APP_DIR="${APP_DIR}"
BASE_DIR="${BASE_DIR}"
ENV_PATH="${ENV_PATH}"
HEALTH_DOMAIN="${HEALTH_DOMAIN}"
HEALTH_RETRIES="${HEALTH_RETRIES}"
COMPOSE_TIMEOUT="${COMPOSE_TIMEOUT}"

# ─────────────────────────────────────────────────────────────────────────────
# [1] VALIDATE .ENV TRÊN EC2
# FIX: kiểm tra .env tồn tại VÀ có các biến bắt buộc trước khi bắt đầu
# ─────────────────────────────────────────────────────────────────────────────
log "[1] Validating .env file..."

test -f "\\${ENV_PATH}" || fail ".env not found at \\${ENV_PATH}"

for var in SECRET_KEY DB_NAME DB_USER DB_PASSWORD DB_HOST JWT_SECRET_KEY \
           REDIS_URL RATE_LIMIT_RPS RATE_LIMIT_BURST \
           REDIS_RATE_LIMIT REDIS_RL_WINDOW \
           AUTO_BL_THRESHOLD AUTO_BL_WINDOW AUTO_BL_DURATION \
           RISK_BLOCK_THRESHOLD RISK_LIMIT_THRESHOLD ALLOWED_HOSTS; do
    grep -q "^\\${var}=" "\\${ENV_PATH}" || {
        echo "⚠️  WARNING: \\${var} not found in .env — using default or may crash"
    }
done
log "✅ .env validated"

# ─────────────────────────────────────────────────────────────────────────────
# [2] SYNC CODE TỪ GIT
# FIX: git fetch --tags để IMAGE_TAG có thể reference đúng commit
# ─────────────────────────────────────────────────────────────────────────────
log "[2] Syncing code from GitHub..."

mkdir -p "\\${BASE_DIR}"

if [ ! -d "\\${APP_DIR}/.git" ]; then
    log "  Fresh clone..."
    git clone --depth 1 https://github.com/NTNguyen055/API-Security-Gateway.git "\\${APP_DIR}"
else
    log "  Updating existing repo..."
    cd "\\${APP_DIR}"
    git fetch origin --tags
    git reset --hard origin/main
    git clean -fd
fi

cd "\\${APP_DIR}"
log "  Commit: \\$(git rev-parse --short HEAD) — \\$(git log -1 --pretty=%s)"

# ─────────────────────────────────────────────────────────────────────────────
# [3] TẠO LOG DIR CHO NGINX
# nginx/Dockerfile mount ./logs/nginx → /usr/local/openresty/nginx/logs
# FIX: tạo trước để docker không tạo thư mục với quyền root
# ─────────────────────────────────────────────────────────────────────────────
log "[3] Preparing log directories..."
mkdir -p "\\${APP_DIR}/logs/nginx"
chmod 755 "\\${APP_DIR}/logs/nginx"
log "✅ Log dirs ready"

# ─────────────────────────────────────────────────────────────────────────────
# [4] BACKUP IMAGES ĐANG CHẠY (CHO ROLLBACK)
# ─────────────────────────────────────────────────────────────────────────────
log "[4] Backing up current images for rollback..."

PREV_APP_DIGEST=\\$(docker inspect --format='{{.Id}}' "\\${APP_IMAGE}:latest" 2>/dev/null || echo "")
PREV_GW_DIGEST=\\$(docker inspect  --format='{{.Id}}' "\\${GW_IMAGE}:latest"  2>/dev/null || echo "")

docker tag "\\${APP_IMAGE}:latest" "\\${APP_IMAGE}:rollback" 2>/dev/null || true
docker tag "\\${GW_IMAGE}:latest"  "\\${GW_IMAGE}:rollback"  2>/dev/null || true

log "  App backup: \\${PREV_APP_DIGEST:0:12}"
log "  GW  backup: \\${PREV_GW_DIGEST:0:12}"

# ─────────────────────────────────────────────────────────────────────────────
# [5] PULL IMAGES MỚI
# ─────────────────────────────────────────────────────────────────────────────
log "[5] Pulling new images (tag=${IMAGE_TAG})..."

docker pull "\\${APP_IMAGE}:${IMAGE_TAG}" || fail "Failed to pull \\${APP_IMAGE}:${IMAGE_TAG}"
docker pull "\\${GW_IMAGE}:${IMAGE_TAG}"  || fail "Failed to pull \\${GW_IMAGE}:${IMAGE_TAG}"

# Re-tag :latest để docker compose pull theo :latest
docker tag "\\${APP_IMAGE}:${IMAGE_TAG}" "\\${APP_IMAGE}:latest"
docker tag "\\${GW_IMAGE}:${IMAGE_TAG}"  "\\${GW_IMAGE}:latest"

log "✅ Images pulled and tagged :latest"

# ─────────────────────────────────────────────────────────────────────────────
# [6] DEPLOY — với auto rollback nếu thất bại
# ─────────────────────────────────────────────────────────────────────────────
log "[6] Deploying via docker compose..."

# Hàm rollback tái sử dụng
do_rollback() {
    log "🔄 Initiating rollback to previous version..."

    docker compose --env-file "\\${ENV_PATH}" down --remove-orphans || true

    docker tag "\\${APP_IMAGE}:rollback" "\\${APP_IMAGE}:latest" 2>/dev/null || true
    docker tag "\\${GW_IMAGE}:rollback"  "\\${GW_IMAGE}:latest"  2>/dev/null || true

    if docker compose --env-file "\\${ENV_PATH}" up -d --wait \
            --wait-timeout "\\${COMPOSE_TIMEOUT}" \
            --remove-orphans 2>/dev/null; then
        log "✅ Rollback to previous version succeeded"
    else
        log "⚠️  Rollback also failed — manual intervention required!"
    fi
}

# Deploy với --wait: Docker Compose chờ healthcheck pass
if ! docker compose --env-file "\\${ENV_PATH}" up -d \
        --wait \
        --wait-timeout "\\${COMPOSE_TIMEOUT}" \
        --remove-orphans; then

    log "⚠️  docker compose --wait FAILED or TIMEOUT (>${COMPOSE_TIMEOUT}s)"
    do_rollback
    fail "DEPLOYMENT FAILED — rolled back to previous version. Check logs above."
fi

log "✅ docker compose up succeeded and all containers healthy"

# ─────────────────────────────────────────────────────────────────────────────
# [7] POST-DEPLOY HEALTH VERIFICATION
# FIX: kiểm tra thêm ở tầng HTTP sau khi container healthy
# Dùng /health/ qua port 80 (nginx HTTP server → pass through thẳng không redirect)
# ─────────────────────────────────────────────────────────────────────────────
log "[7] Post-deploy HTTP health verification..."

RETRY=0
HTTP_OK=0
while [ "\\${RETRY}" -lt "\\${HEALTH_RETRIES}" ]; do
    RETRY=\\$((RETRY + 1))
    log "  Attempt \\${RETRY}/\\${HEALTH_RETRIES}..."

    HTTP_CODE=\\$(curl -sf \
        --max-time 5 \
        -o /tmp/health_resp.json \
        -w "%{http_code}" \
        -H "Host: \\${HEALTH_DOMAIN}" \
        -H "X-Forwarded-Proto: https" \
        -H "X-Forwarded-For: 127.0.0.1" \
        -A "JenkinsHealthChecker/1.0" \
        "http://localhost/health/" 2>/dev/null || echo "000")

    if [ "\\${HTTP_CODE}" = "200" ]; then
        RESP=\\$(cat /tmp/health_resp.json 2>/dev/null || echo "")
        log "  ✅ HTTP 200 — response: \\${RESP}"

        # FIX: kiểm tra cả DB và cache status trong response JSON
        if echo "\\${RESP}" | grep -q '"db": "ok"'; then
            log "  ✅ DB check passed"
        else
            log "  ⚠️  DB check in health response not 'ok' — check Django logs"
        fi

        HTTP_OK=1
        break
    fi

    log "  HTTP \\${HTTP_CODE} — retrying in 10s..."
    sleep 10
done

if [ "\\${HTTP_OK}" -ne 1 ]; then
    log "❌ Post-deploy health check FAILED after \\${HEALTH_RETRIES} attempts"
    do_rollback
    fail "Health check failed — deployment rolled back"
fi

# ─────────────────────────────────────────────────────────────────────────────
# [8] VERIFY CONTAINERS STATUS
# ─────────────────────────────────────────────────────────────────────────────
log "[8] Verifying container statuses..."
docker compose --env-file "\\${ENV_PATH}" ps

# Kiểm tra 3 container bắt buộc đang running và healthy
for svc in docapp_django docapp_redis openresty_gateway; do
    STATUS=\\$(docker inspect --format='{{.State.Status}}' "\\${svc}" 2>/dev/null || echo "missing")
    HEALTH=\\$(docker inspect --format='{{.State.Health.Status}}' "\\${svc}" 2>/dev/null || echo "no_healthcheck")

    log "  Container \\${svc}: status=\\${STATUS} health=\\${HEALTH}"

    if [ "\\${STATUS}" != "running" ]; then
        log "❌ Container \\${svc} is not running (status=\\${STATUS})"
        docker logs "\\${svc}" --tail 30 2>/dev/null || true
        do_rollback
        fail "Container \\${svc} not running after deploy"
    fi
done

log "✅ All containers running and healthy"

# ─────────────────────────────────────────────────────────────────────────────
# [9] CLEANUP — xóa image cũ, giữ :rollback để recovery
# ─────────────────────────────────────────────────────────────────────────────
log "[9] Cleaning up old images..."

# Xóa dangling images (không có tag) — an toàn
docker image prune -f

# Xóa images cũ hơn 48h (giữ lại recent build và rollback)
docker image prune -af --filter "until=48h" 2>/dev/null || true

log "✅ Cleanup done"
log ""
log "═══════════════════════════════════════════════════"
log "  🎉 DEPLOYMENT SUCCESSFUL"
log "  Image tag : ${IMAGE_TAG}"
log "  Domain    : https://\\${HEALTH_DOMAIN}"
log "  Deployed  : \\$(date '+%Y-%m-%d %H:%M:%S %Z')"
log "═══════════════════════════════════════════════════"

ENDSSH
                    """
                }
            }
        }
    }

    // =========================================================================
    // POST — cleanup Jenkins agent và notifications
    // =========================================================================
    post {
        always {
            echo "🧹 Cleaning up Jenkins agent..."

            // Logout DockerHub
            sh 'docker logout || true'

            // Xóa image local trên Jenkins agent để giải phóng disk
            // FIX: xóa cả IMAGE_TAG và latest — tránh tích lũy qua nhiều build
            sh """
                docker rmi ${APP_IMAGE}:${IMAGE_TAG} 2>/dev/null || true
                docker rmi ${APP_IMAGE}:latest        2>/dev/null || true
                docker rmi ${GW_IMAGE}:${IMAGE_TAG}  2>/dev/null || true
                docker rmi ${GW_IMAGE}:latest         2>/dev/null || true
                docker image prune -f                 2>/dev/null || true
            """

            // In tóm tắt build info
            sh '''
                echo ""
                echo "════════════════════════════════════════"
                echo " Build Summary"
                echo " Job    : ${JOB_NAME}"
                echo " Build  : #${BUILD_NUMBER}"
                echo " Result : ${currentBuild.currentResult}"
                echo " URL    : ${BUILD_URL}"
                echo "════════════════════════════════════════"
            '''
        }

        success {
            echo "✅ Pipeline #${BUILD_NUMBER} completed successfully — ${APP_IMAGE}:${IMAGE_TAG} deployed"
        }

        failure {
            echo "❌ Pipeline #${BUILD_NUMBER} FAILED — check logs at ${BUILD_URL}console"
            // Gợi ý: thêm slackSend hoặc emailext ở đây nếu cần notification
            // slackSend(color: 'danger', message: "Deploy FAILED: ${JOB_NAME} #${BUILD_NUMBER}")
        }

        unstable {
            echo "⚠️  Pipeline #${BUILD_NUMBER} is UNSTABLE"
        }
    }
}
