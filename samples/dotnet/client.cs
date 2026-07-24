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
            string command = string.Join(" ", args);
            byte[] cmdBytes = Encoding.UTF8.GetBytes(command);

            // Execute command
            IntPtr output = IntPtr.Zero;
            IntPtr errOutput = IntPtr.Zero;
            int result = rpcExec(cmdBytes, ref output, ref errOutput);

            // Show stderr output
            if (errOutput != IntPtr.Zero)
            {
                string? errString = Marshal.PtrToStringAnsi(errOutput);
                if (!string.IsNullOrEmpty(errString))
                {
                    Console.Error.WriteLine(errString);
                }
                Marshal.FreeHGlobal(errOutput);
            }
            // Show output
            if (output != IntPtr.Zero)
            {
                string? outputString = Marshal.PtrToStringAnsi(output);
                if (!string.IsNullOrEmpty(outputString))
                {
                    Console.WriteLine(outputString);
                }
                Marshal.FreeHGlobal(output);
            }

            Console.WriteLine($"Exit code: {result}");
            return result;
        }
    }
}
