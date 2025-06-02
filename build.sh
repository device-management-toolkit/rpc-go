# Get version from the first argument
version=$1

# Download the certificate to the initial location
wget -O ./internal/certs/OnDie_CA_RootCA_Certificate.cer \
    https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer 

# Check if the download was successful (non-zero file size)
if [ -s ./internal/certs/OnDie_CA_RootCA_Certificate.cer ]; then
    # Move the downloaded certificate to the trusted store
    mv ./internal/certs/OnDie_CA_RootCA_Certificate.cer \
        ./internal/certs/trustedstore/OnDie_CA_RootCA_Certificate.cer
    echo "Certificate moved to trusted store."
else
    # Remove the file if the download failed
    rm -f ./internal/certs/OnDie_CA_RootCA_Certificate.cer
    echo "Download failed, file removed."
fi

# Build for Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X 'github.com/device-management-toolkit/rpc-go/v2/pkg/utils.ProjectVersion=$version'" -trimpath -o rpc_linux_x64 ./cmd/rpc/main.go
CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags "-s -w -X 'github.com/device-management-toolkit/rpc-go/v2/pkg/utils.ProjectVersion=$version'" -trimpath -o rpc_linux_x86 ./cmd/rpc/main.go

# Build for Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X 'github.com/device-management-toolkit/rpc-go/v2/pkg/utils.ProjectVersion=$version'" -trimpath -o rpc_windows_x64.exe ./cmd/rpc/main.go 
CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags "-s -w -X 'github.com/device-management-toolkit/rpc-go/v2/pkg/utils.ProjectVersion=$version'" -trimpath -o rpc_windows_x86.exe ./cmd/rpc/main.go

# Build library for Linux
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -trimpath -buildmode=c-shared -o rpc.so.$version ./cmd/rpc

# Mark the Unix system outputs as executable
chmod +x rpc_linux_x64
chmod +x rpc_linux_x86

# Add them to tar files respectively
tar cvfpz rpc_linux_x64.tar.gz rpc_linux_x64
tar cvfpz rpc_linux_x86.tar.gz rpc_linux_x86
tar cvfpz rpc_so_x64.tar.gz rpc.so.$version

# Add Windows build to a zip file
zip rpc_windows_x64.zip rpc_windows_x64.exe
zip rpc_windows_x86.zip rpc_windows_x86.exe

# Generate license files
go-licenses save ./... --save_path=licensefiles

# Create a zip file for license files
zip -r licenses.zip licensefiles/