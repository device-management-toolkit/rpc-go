# CSharp Sample Leveraging rpc-go as a Library

## Howto for Ubuntu Linux

Install .NET 10 SDK if needed via apt (recommended over snap to avoid glibc 
compatibility issues with the shared library):

```shell
sudo apt-get install -y dotnet-sdk-10.0
```

From the rpc-go root directory, build the CSharp executable:

```shell
dotnet build samples/dotnet/client.csproj
```

This creates the directory `samples/dotnet/bin/Debug/net10.0/` with `client.dll`.

Build a shared object library from the rpc-go sources and place it in the bin
folder created above:

NOTE: REQUIRES GCC INSTALLATION  
NOTE: standard library naming presented here  
NOTE: assumes the dotnet SDK version is 10.0, check the bin path and adjust as needed

```shell
go build -buildmode=c-shared -o samples/dotnet/bin/Debug/net10.0/librpc.so ./cmd/rpc
```

On Ubuntu, there seems to be issues with Console.WriteLine showing up in
the command line terminal. The sample can be run as either a native
executable or via dotnet using the .dll directly.
NOTE: Run from the rpc-go root directory, or navigate to the build output directory.

```shell
sudo dotnet samples/dotnet/bin/Debug/net10.0/client.dll amtinfo
```