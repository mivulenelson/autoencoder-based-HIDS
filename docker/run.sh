#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AUTOENCODER-HIDS  |  run.sh  —  complete setup and launch script
#
# Run from your project root:
#   chmod +x docker/run.sh
#   ./docker/run.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/docker"

echo "═══════════════════════════════════════════════════"
echo "  AUTOENCODER-HIDS  |  Docker Launcher"
echo "  Project: $PROJECT_ROOT"
echo "═══════════════════════════════════════════════════"

cd "$PROJECT_ROOT"

# ── Step 1: Activate venv ──────────────────────────────────────────────────
if [ -f "env/bin/activate" ]; then
    source env/bin/activate
    echo "✓  venv activated"
else
    echo "⚠  No env/ venv found — using system Python"
fi

# ── Step 2: Generate threshold.yaml if missing ────────────────────────────
if [ ! -f "configs/threshold.yaml" ] && [ ! -f "models/threshold.yaml" ]; then
    echo ""
    echo "── Generating threshold.yaml ──────────────────────────"
    if [ -f "models/baseline_ae.keras" ] && [ -f "models/scaler.pkl" ]; then
        python docker/generate_threshold.py
    else
        echo "  ERROR: models/baseline_ae.keras or models/scaler.pkl not found."
        echo "  Place your trained model files in the models/ directory first."
        exit 1
    fi
else
    echo "✓  threshold.yaml exists"
fi

# ── Step 3: Copy env file ─────────────────────────────────────────────────
if [ ! -f "docker/.env" ]; then
    cp "docker/.env.example" "docker/.env"
    echo "✓  docker/.env created from example"
fi

# ── Step 4: Load model weights into Docker volume ─────────────────────────
echo ""
echo "── Loading model files into Docker volumes ────────────"

# Create volumes if they don't exist yet
docker volume create hids_models  > /dev/null 2>&1 || true
docker volume create hids_configs > /dev/null 2>&1 || true
docker volume create hids_db      > /dev/null 2>&1 || true
docker volume create hids_logs    > /dev/null 2>&1 || true

# Copy model files
docker run --rm \
    -v "$PROJECT_ROOT/models":/src:ro \
    -v hids_models:/dst \
    alpine sh -c "
        [ -f /src/baseline_ae.keras ] && cp -f /src/baseline_ae.keras /dst/ && echo ' Copied baseline_ae.keras' || echo ' WARNING: baseline_ae.keras not found'
        [ -f /src/scaler.pkl ]        && cp -f /src/scaler.pkl /dst/        && echo ' Copied scaler.pkl'        || echo ' WARNING: scaler.pkl not found'
        [ -f /src/threshold.yaml ]    && cp -f /src/threshold.yaml /dst/    && echo ' Copied threshold.yaml'    || true
    "

# Copy threshold.yaml to configs volume
if [ -f "configs/threshold.yaml" ]; then
    docker run --rm \
        -v "$PROJECT_ROOT/configs":/src:ro \
        -v hids_configs:/dst \
        alpine sh -c "cp /src/threshold.yaml /dst/ && echo '  Copied configs/threshold.yaml'"
elif [ -f "models/threshold.yaml" ]; then
    docker run --rm \
        -v "$PROJECT_ROOT/models":/src:ro \
        -v hids_configs:/dst \
        alpine sh -c "cp /src/threshold.yaml /dst/ && echo '  Copied models/threshold.yaml → configs volume'"
fi

# ── Step 5: Allow X11 ─────────────────────────────────────────────────────
echo ""
echo "── Setting up display ─────────────────────────────────"
xhost +local:docker 2>/dev/null && echo "✓  xhost +local:docker" || echo "⚠  xhost failed — dashboard may not open"

# ── Step 6: Launch ────────────────────────────────────────────────────────
echo ""
echo "── Launching containers ───────────────────────────────"
cd "$DOCKER_DIR"
docker compose --env-file .env --profile gui up --build "$@"