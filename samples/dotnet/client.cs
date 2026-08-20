/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

using System.Runtime.InteropServices;
using System.Text;

namespace ClientAgent
{
    class RpcClientAgent
    {
        private const string LibraryName = "rpc";

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int rpcCheckAccess();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int rpcExec([In] byte[] rpccmd, ref IntPtr output, ref IntPtr errOutput);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void rpcFree(IntPtr ptr);

        private const int SUCCESS = 0;

        static void Main(string[] args)
        {
            try
            {
                var client = new RpcClientAgent();
                Environment.Exit(client.Run(args));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }

        private int Run(string[] args)
        {
            // Check access
            if (rpcCheckAccess() != SUCCESS)
            {
                Console.Error.WriteLine("RPC access failed - try running as administrator");
                Console.WriteLine("Exit code: 1");
                return 1;
            }

            // Build command
            string command = BuildCommand(args);
            byte[] cmdBytes = Encoding.UTF8.GetBytes(command + "\0");

            // Execute command
            IntPtr output = IntPtr.Zero;
            IntPtr errOutput = IntPtr.Zero;
            int result = rpcExec(cmdBytes, ref output, ref errOutput);

            // Show stderr output
            if (errOutput != IntPtr.Zero)
            {
                string? errString = Marshal.PtrToStringUTF8(errOutput);
                if (!string.IsNullOrEmpty(errString))
                {
                    Console.Error.Write(errString);
                }
                rpcFree(errOutput);
            }
            // Show output
            if (output != IntPtr.Zero)
            {
                string? outputString = Marshal.PtrToStringUTF8(output);
                if (!string.IsNullOrEmpty(outputString))
                {
                    Console.Write(outputString);
                }
                rpcFree(output);
            }

            Console.WriteLine($"Exit code: {result}");
            return result;
        }

        private static string BuildCommand(string[] args)
        {
            var builder = new StringBuilder();
            for (int index = 0; index < args.Length; index++)
            {
                if (index > 0)
                {
                    builder.Append(' ');
                }

                builder.Append(EscapeArgument(args[index]));
            }

            return builder.ToString();
        }

        private static string EscapeArgument(string arg)
        {
            if (!string.IsNullOrEmpty(arg) && !arg.Contains(' ') && !arg.Contains('"') && !arg.Contains('\r') && !arg.Contains('\n'))
            {
                return arg;
            }

            return '"' + arg.Replace("\"", "\"\"") + '"';
        }
    }
}
