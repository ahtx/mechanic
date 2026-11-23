# Manual end-to-end run with a real model. Run ONLY inside a throwaway container, for example:
#   docker run --rm --network host -v $PWD:/opt/mechanic:ro -e MECHANIC_HOME=/root/.mech v27-sandbox bash /opt/mechanic/tests/e2e_real_model.sh
# Set EP below to your OpenAI-compatible endpoint.
set -e
# setup 1: nginx config with a missing semicolon
sed -i "s/worker_connections 768;/worker_connections 768/" /etc/nginx/nginx.conf
nginx -t 2>&1 | tail -1 || true
# setup 2: old and new logs
mkdir -p /var/log/app
for i in 1 2 3; do echo old > /var/log/app/old$i.log; touch -d "60 days ago" /var/log/app/old$i.log; done
echo new > /var/log/app/today.log; echo keep > /var/log/app/README
cd /opt/mechanic
EP=${EP:-http://localhost:8000/v1}
python3 -m mechanic run --auto --log --endpoint $EP --max-steps 10 "nginx -t fails on this machine. Find the syntax error in /etc/nginx/nginx.conf and fix it so that nginx -t passes. Do not change anything else."
python3 -m mechanic run --auto --log --endpoint $EP --max-steps 10 "Free some space: delete the .log files in /var/log/app that are older than 30 days. Keep everything else."
echo "=== RESULT"; nginx -t 2>&1 | tail -1; ls /var/log/app
echo "=== LOGS"; python3 -m mechanic logs
for f in $MECHANIC_HOME/sessions/*.jsonl; do echo "--- $f"; cat $f; done
echo "=== CONTRIBUTE"; printf "a\na\nI agree\n\n" | python3 -m mechanic contribute --file
echo "=== BUNDLE"; cat $MECHANIC_HOME/outbox/*
