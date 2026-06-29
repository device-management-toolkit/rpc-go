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
	go test -run=^$$ -fuzz=^FuzzActivate$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzActivateURL$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzActivateProfile$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzActivatePassword$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzActivateFlagCombinations$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzVersion$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzVersionFlagCombinations$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzAmtInfo$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzAmtInfoURL$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzAmtInfoFlagCombinations$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzConfigure$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzConfigureSubcommand$$ -fuzztime=5m ./internal/cli
	go test -run=^$$ -fuzz=^FuzzConfigureFlagCombinations$$ -fuzztime=5m ./internal/cli

fuzz-short: ### run fuzz tests for short duration (30 seconds per test)
	@echo "Running quick fuzz tests for 30 seconds each..."
	go test -run=^$$ -fuzz=^FuzzDeactivate$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzDeactivateURL$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzDeactivatePassword$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzDeactivateFlagCombinations$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzActivate$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzActivateURL$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzActivateProfile$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzActivatePassword$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzActivateFlagCombinations$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzVersion$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzVersionFlagCombinations$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzAmtInfo$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzAmtInfoURL$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzAmtInfoFlagCombinations$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzConfigure$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzConfigureSubcommand$$ -fuzztime=30s ./internal/cli
	go test -run=^$$ -fuzz=^FuzzConfigureFlagCombinations$$ -fuzztime=30s ./internal/cli

fuzz-regression: ### run fuzz tests with existing corpus only (no new inputs)
	@echo "Running fuzz regression tests..."
	go test ./internal/cli -run=^$$ -fuzz=^FuzzDeactivate$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzDeactivateURL$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzDeactivatePassword$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzDeactivateFlagCombinations$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzActivate$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzActivateURL$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzActivateProfile$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzActivatePassword$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzActivateFlagCombinations$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzVersion$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzVersionFlagCombinations$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzAmtInfo$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzAmtInfoURL$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzAmtInfoFlagCombinations$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzConfigure$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzConfigureSubcommand$$ -fuzztime=1x
	go test ./internal/cli -run=^$$ -fuzz=^FuzzConfigureFlagCombinations$$ -fuzztime=1x
