build:
	go build ./cmd/rpc

mock: ### run mockgen
	mockgen -source ./internal/interfaces/wsman.go -destination ./internal/mocks/wsman_mock.go -package=mock
	mockgen -source ./internal/amt/commands.go -destination ./internal/mocks/amt_mock.go -package=mock