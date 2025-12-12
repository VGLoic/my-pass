#!/bin/bash

echo "Launching docker compose"

docker compose -f compose.integration.yaml up -d

echo "Waiting for the database to be ready..."

# Set timeout duration
timeout=20
start_time=$(date +%s)

# Wait for the database container to be healthy
until [[ $(docker inspect --format='{{json .State.Health.Status}}' integration-db) == '"healthy"' ]]; do
    echo "Database is not yet ready, waiting..."
    sleep 1

    # Check if timeout has been reached
    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))
    if [[ $elapsed_time -ge $timeout ]]; then
        echo "Timeout reached. Exiting."
        docker compose -f compose.integration.yaml down -v
        exit 1
    fi
done

cargo test --tests
test_exit_status=$?

echo "Removing docker container and volume"

docker compose -f compose.integration.yaml down -v

# Check the exit status of the tests and exit accordingly
if [ $test_exit_status -eq 0 ]; then
    echo "Integration tests passed."
    exit 0
else
    echo "Integration tests failed."
    exit 1
fi
