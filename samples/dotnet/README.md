# CSharp sample leveraging rpc-go as a library

## Howto for Ubuntu Linux
Install dotnet sdk if needed via apt (recommended over snap to avoid glibc compatibility issues with the shared library)
```shell
sudo apt-get install -y dotnet-sdk-8.0
```

From the rpc-go root directory, build the csharp executable
```shell
dotnet build samples/dotnet/client.csproj
```
This will create the directory samples/dotnet/bin/Debug/net8.0/  

Build a shared object library from the rpc-go sources
and just put it directly into the bin folder created above  
NOTE: REQUIRES GCC INSTALLATION  
NOTE: standard library naming presented here  
NOTE: assumes the dotnet SDK version is 8.0, check the bin path and adjust as needed
```
# at the root of the rpc-go project with the command
CGO_ENABLED=1 go build -buildmode=c-shared -o samples/dotnet/bin/Debug/net8.0/librpc.so ./cmd/rpc
```

On Ubuntu, there seems to be issues with Console.WriteLine showing up in
the command line terminal. The sample can be run as either a native executable
or via `dotnet` using the .dll directly.  
**NOTE: Run from the rpc-go root directory, or navigate to the build output directory**
```shell
# Option 1: Run native executable from build output directory
cd samples/dotnet/bin/Debug/net8.0/
sudo ./client version
sudo ./client amtinfo

# Option 2: Run via dotnet from build output directory
cd samples/dotnet/bin/Debug/net8.0/
sudo dotnet client.dll version
sudo dotnet client.dll amtinfo

# Or from rpc-go root with absolute path
sudo /full/path/to/rpc-go/samples/dotnet/bin/Debug/net8.0/client version
sudo dotnet /full/path/to/rpc-go/samples/dotnet/bin/Debug/net8.0/client.dll version
```

The sample wraps rpc-go and accepts the same commands as the rpc CLI. Pass RPC commands and flags as arguments.
