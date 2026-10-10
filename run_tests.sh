#!/bin/bash

echo "Running DevSecOps Pre-Commit Hook Test..."
echo "-----------------------------------------"

python3 pre_commit_hook.py test_mock_secret.py test_package.json test_requirements.txt

EXIT_CODE=$?

echo "-----------------------------------------"
if [ $EXIT_CODE -ne 0 ]; then
    echo "Test passed! Hook correctly identified the mock vulnerabilities and failed the commit."
else
    echo "Test failed! Hook should have failed but exited with code 0."
fi