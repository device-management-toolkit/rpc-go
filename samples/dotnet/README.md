# CSharp Sample Leveraging rpc-go as a Library

## Howto for Ubuntu Linux

Install .NET 9 SDK if needed via apt (recommended over snap to avoid glibc 
compatibility issues with the shared library):

NOTE: this requires the Microsoft package repository to be configured first.
If it is not already configured on your system, follow the official Ubuntu
instructions at https://learn.microsoft.com/dotnet/core/install/linux-ubuntu.

```shell
sudo apt-get install -y dotnet-sdk-9.0
```

If .NET 9 is not available in apt, use Microsoft's install script:

```shell
curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 9.0 --install-dir ~/.dotnet
export PATH="$HOME/.dotnet:$PATH"
```

From the rpc-go root directory, build the CSharp executable:

```shell
dotnet build samples/dotnet/client.csproj
```

This creates the directory `samples/dotnet/bin/Debug/net9.0/` with `client.dll`.

Build a shared object library from the rpc-go sources and place it in the bin
folder created above:

NOTE: REQUIRES GCC INSTALLATION  
NOTE: standard library naming presented here  
NOTE: assumes the dotnet SDK version is 9.0, check the bin path and adjust as needed

```shell
go build -buildmode=c-shared -o samples/dotnet/bin/Debug/net9.0/librpc.so ./cmd/rpc
```

On Ubuntu, there seems to be issues with Console.WriteLine showing up in
the command line terminal. The sample can be run as either a native
executable or via dotnet using the .dll directly.
NOTE: Run from the rpc-go root directory, or navigate to the build output directory.

```shell
sudo dotnet samples/dotnet/bin/Debug/net9.0/client.dll
```