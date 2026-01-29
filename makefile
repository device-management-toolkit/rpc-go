build:
	go build ./cmd/rpc

mock: ### run mockgen
	mockgen -source ./internal/interfaces/wsman.go -destination ./internal/mocks/wsman_mock.go -package=mock
	mockgen -source ./internal/amt/commands.go -destination ./internal/mocks/amt_mock.go -package=mock

fuzz: ### run fuzz tests for extended duration (5 minutes per test)
	@echo "Running fuzz tests for 5 minutes each..."
	go test -run=^$$ -fuzz=^FuzzDeactivate$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzDeactivateURL$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzDeactivatePassword$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzDeactivateFlagCombinations$$ -fuzztime=5m ./internal/cli

fuzz-short: ### run fuzz tests for short duration (30 seconds per test)
	@echo "Running quick fuzz tests for 30 seconds each..."
	go test -run=^$$ -fuzz=^FuzzDeactivate$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzDeactivateURL$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzDeactivatePassword$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzDeactivateFlagCombinations$$ -fuzztime=30s ./internal/cli

fuzz-regression: ### run fuzz tests with existing corpus only (no new inputs)
	@echo "Running fuzz regression tests..."
	go test ./internal/cli -run=^$$ -fuzz=^FuzzDeactivate$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzDeactivateURL$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzDeactivatePassword$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzDeactivateFlagCombinations$$ -fuzztime=1x