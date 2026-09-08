#!/bin/bash
set -e
cd /home/azaki/Project/Browser-Artifact-Analyzer
rm -rf .git input output __pycache__
git init -b main
git config user.name "thanhhao06"
git config user.email "thanhhao06@users.noreply.github.com"
git add .
git commit -m "Upgrade Artifact Collector v2.0"
git remote add origin https://github.com/thanhhao06/Artifact-Collector.git
rm -f setup_git.sh
echo "Clean git repository prepared successfully!"
git log --oneline
