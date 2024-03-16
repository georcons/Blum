using System; 
using System.IO;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Principal;
using System.Threading;

namespace Blum
{
    // HexTools --> Temp class
    class HexTools
    {
        public static byte[] HexToByteArray(string hex)
        {
            int l = hex.Length / 2;
            byte[] output = new byte[l];
            for (int i = 0; i < l; i++)
            {
                char a = hex[2 * i];
                char b = hex[2 * i + 1];
                output[i] = (byte)(SymbolHex(a) * 16 + SymbolHex(b));
            }
            return output;
        }

        public static byte SymbolHex(char s)
        {
            switch (s)
            {
                case '1':
                    return 1;
                case '2':
                    return 2;
                case '3':
                    return 3;
                case '4':
                    return 4;
                case '5':
                    return 5;
                case '6':
                    return 6;
                case '7':
                    return 7;
                case '8':
                    return 8;
                case '9':
                    return 9;
                case 'a':
                case 'A':
                    return 10;
                case 'b':
                case 'B':
                    return 11;
                case 'c':
                case 'C':
                    return 12;
                case 'd':
                case 'D':
                    return 13;
                case 'e':
                case 'E':
                    return 14;
                case 'f':
                case 'F':
                    return 15;
                case '0':
                default:
                    return 0;
            }
        }
    }

    class IPAddressRange
    {
        readonly AddressFamily addressFamily;
        readonly public byte[] lowerBytes;
        readonly public byte[] upperBytes;

        public IPAddressRange(IPAddress lowerInclusive, IPAddress upperInclusive)
        {
            uint a = BitConverter.ToUInt32(lowerInclusive.GetAddressBytes(), 0);
            uint b = BitConverter.ToUInt32(upperInclusive.GetAddressBytes(), 0);
            this.addressFamily = lowerInclusive.AddressFamily;
            this.lowerBytes = lowerInclusive.GetAddressBytes();
            this.upperBytes = upperInclusive.GetAddressBytes();
        }

        public IPAddress[] GetAllIPs()
        {
            byte[] CurrentBytes = new byte[] { lowerBytes[0], lowerBytes[1], lowerBytes[2], lowerBytes[3] };
            uint begin = lowerBytes[0] * (uint)Math.Pow(256, 3) + lowerBytes[1] * (uint)Math.Pow(256, 2) + lowerBytes[2] * (uint)Math.Pow(256, 1) + lowerBytes[3];
            uint end = upperBytes[0] * (uint)Math.Pow(256, 3) + upperBytes[1] * (uint)Math.Pow(256, 2) + upperBytes[2] * (uint)Math.Pow(256, 1) + upperBytes[3];
            uint count = end - begin + 1;
            IPAddress[] output = new IPAddress[count];
            for (uint i = begin; i <= end; i++)
            {
                byte[] b = new byte[4];
                uint k = i;
                for (int j = 3; j >= 0; j--) { b[j] = j == 3 ? (byte)(k % 256) : (byte)(k % 256); k /= 256; }
                output[i - begin] = new IPAddress(b);
            }
            return output;

        }

        public bool IsInRange(IPAddress address)
        {
            if (address.AddressFamily != addressFamily)
            {
                return false;
            }

            byte[] addressBytes = address.GetAddressBytes();

            bool lowerBoundary = true, upperBoundary = true;

            for (int i = 0; i < this.lowerBytes.Length &&
                (lowerBoundary || upperBoundary); i++)
            {
                if ((lowerBoundary && addressBytes[i] < lowerBytes[i]) ||
                    (upperBoundary && addressBytes[i] > upperBytes[i]))
                {
                    return false;
                }

                lowerBoundary &= (addressBytes[i] == lowerBytes[i]);
                upperBoundary &= (addressBytes[i] == upperBytes[i]);
            }

            return true;
        }
    }

    class ScanData
    {
        public IPAddress[] HostsUp = new IPAddress[0];
        private bool Busy = false;
        IPAddressRange range;

        public ScanData(IPAddressRange range)
        {
            this.range = range;
        }

        private bool IsAlreadyListed(IPAddress IP)
        {
            bool output = false;
            byte[] Bytes = IP.GetAddressBytes();
            for (int i = 0; i < HostsUp.Length && !output; i++)
            {
                byte[] Host = HostsUp[i].GetAddressBytes();
                output = (Host[0] == Bytes[0] && Host[1] == Bytes[1] && Host[2] == Bytes[2] && Host[3] == Bytes[3]);
            }
            return output;
        }

        public void AddIP(IPAddress IP)
        {
            if (range.IsInRange(IP) && !IsAlreadyListed(IP))
            {
                while (Busy) { /* WAIT */ }
                Busy = true;
                IPAddress[] newArr = new IPAddress[HostsUp.Length + 1];
                for (int i = 0; i < HostsUp.Length; i++) newArr[i] = HostsUp[i];
                newArr[HostsUp.Length] = IP;
                HostsUp = newArr;
                Busy = false;
            }
        }
    }

    enum BlumCommand
    { 
        Interfaces, Scan, Help, Error
    }

    class BlumStrings
    {
        public const string ResolvingError = "BlUM> Unable to resolve your command. Check << blum -h >>.";
        public const string AdminNotice = "BlUM> Scans require administrator privilege to run.";
        public const string NoValidInterface = "BlUM> Unable to find a valid interface.";
        public const string InvalidInterface = "BlUM> Chosen interface is invalid.";
        public const string Help = "BlUM> USAGE: \r\n" +
                                   "blum [Arguments] [Start IP]-[End IP]\r\n" + 
                                   "\n" +
                                   "BlUM> ARGUMENTS: \r\n" +
                                   "-I             ---> Shows list of interfaces to choose\r\n" +
                                   "-i [int]       ---> Chooses an interface (default: first with an IP)\r\n" +
                                   "-oN [string]   ---> Sets output file\r\n" +
                                   "-h             ---> Shows this help menu\r\n" + 
                                   "\n" +
                                   "BlUM> EXAMPLES: \r\n" +
                                   "blum -I\r\n" +
                                   "blum -i 5 192.168.0.0-192.168.255.255\r\n" +
                                   "blum -oN output.txt 192.168.1.1-192.168.1.255\r\n" +
                                   "blum -i 3 -oN log.txt 10.0.0.0-10.255.255.255\r\n" + 
                                   "\n" +
                                   "BlUM> NOTE: \r\n" +
                                   "Administator rights are needed for scanning.";
    }

    class BlumValues
    {
        static public int WaitAnalyzer = 2000;
        static public int TimeOut = 5600;
        static public int PacketCountCooldown = 18;
        static public int PacketCooldown = 7;
    }

    class BlumUtils
    {
        public static bool IsAdmin()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        public static void ClearCurrentConsoleLine()
        {
            int currentLineCursor = Console.CursorTop;
            Console.SetCursorPosition(0, Console.CursorTop);
            for (int i = 0; i < Console.WindowWidth; i++)
                Console.Write(" ");
            Console.SetCursorPosition(0, currentLineCursor);
        }
    }

    class BlumArguments
    {
        readonly public BlumCommand Command;
        readonly public IPAddress StartIPAddress, EndIPAddress;
        readonly public int InterfaceIndex = -1;
        readonly public bool OutputFile;
        readonly public string OutputFilePath;

        public BlumArguments(string[] args)
        {
            this.InterfaceIndex = -1;
            this.OutputFilePath = String.Empty;
            this.StartIPAddress = IPAddress.None;
            this.EndIPAddress = IPAddress.None;
            this.Command = BlumCommand.Error;

            int InterfaceCommandPos = Array.IndexOf(args, "-I");
            int InterfaceIndexPos = Array.IndexOf(args, "-i");
            int HelpCommandPos = Array.IndexOf(args, "-h");
            int OutputFilePos = Array.IndexOf(args, "-oN");

            if (args.Length == 0) { this.Command = BlumCommand.Error; return; }
            if ((InterfaceCommandPos != -1 || HelpCommandPos != -1) && args.Length != 1) { this.Command = BlumCommand.Error; return; }
            if (InterfaceCommandPos != -1) { this.Command = BlumCommand.Interfaces; return; }
            if (HelpCommandPos != -1) { this.Command = BlumCommand.Help; return; }          

            if (InterfaceIndexPos != -1)
            {
                if (InterfaceIndexPos >= args.Length - 2) { this.Command = BlumCommand.Error; return; }
                else if (!int.TryParse(args[InterfaceIndexPos + 1], out this.InterfaceIndex)) { this.Command = BlumCommand.Error; return; }
            }

            if (OutputFilePos != -1)
            {
                if (OutputFilePos >= args.Length - 2) { this.Command = BlumCommand.Error; return; }
                else { this.OutputFilePath = args[OutputFilePos + 1]; this.OutputFile = true; }
            }

            string[] IPs = args[args.Length - 1].Split('-');
            if (IPs.Length == 2 && IPAddress.TryParse(IPs[0], out this.StartIPAddress) && IPAddress.TryParse(IPs[1], out this.EndIPAddress)) this.Command = BlumCommand.Scan;
        }

        public bool PickUpInterface(LibPcapLiveDeviceList libs, out ICaptureDevice output)
        {
            output = null;

            if (this.InterfaceIndex == -1)
            {
                for (int i = 0; i < libs.Count; i++)
                {
                    if (libs[i].Addresses.Count >= 2)
                    {
                        output = libs[i];
                        return true;
                    }
                }
                return false;
            }

            if (this.InterfaceIndex < libs.Count && this.InterfaceIndex >= 0 && libs[this.InterfaceIndex].Addresses.Count >= 2)
            {
                output = libs[this.InterfaceIndex];
                return true;
            }

            return false;
        }
    }

    class BlumPacketAnalyzer
    {
        private IPAddressRange Range;
        readonly public ScanData Data;
        private bool Listening = false;
        byte[] buffer = new byte[65536];
        ICaptureDevice device;

        public BlumPacketAnalyzer(IPAddressRange Range, ICaptureDevice device)
        {
            this.Range = Range;
            this.device = device;
            this.Data = new ScanData(Range);
        }

        public void Listen()
        {
            if (!Listening)
            {
                device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(Listen_Callback);
                device.Open();
                device.Filter = "icmp";
                device.StartCapture();
                Listening = true;
            }
        }

        public void Stop()
        {
            if (Listening && device.Started) device.StopCapture(); 
        }
        private void Listen_Callback(object sender, PacketCapture packet)
        {
            byte[] dat = packet.Data.ToArray();
            if (dat.Length > 29)
            {
                byte[] ipBytes = new byte[] { dat[26], dat[27], dat[28], dat[29] };
                IPAddress ip = new IPAddress(ipBytes);
                this.Data.AddIP(ip);
            }
        }
    }

    class BlumPacketSender
    {
        // To be updated with more ICMP types
        static string pingReqHex = "08004d5a000100016162636465666768696a6b6c6d6e6f7071727374757677616263646566676869";
        static string timeReqHex = "0d003761bb9e0000000000000000000000000000";

        readonly IPAddress[] Addresses;
        byte[] icmp_req_ping = new byte[0], icmp_req_time = new byte[0];

        public BlumPacketSender(IPAddressRange Range)
        {
            this.Addresses = Range.GetAllIPs();
            this.icmp_req_ping = HexTools.HexToByteArray(pingReqHex);
            this.icmp_req_time = HexTools.HexToByteArray(timeReqHex);
        }

        public void Send(bool verbose)
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Raw, System.Net.Sockets.ProtocolType.Icmp);
            int count = 0;

            foreach (IPAddress ip in Addresses)
            {
                IPEndPoint iep = new IPEndPoint(ip, 0);
                s.Connect(iep);
                s.Send(this.icmp_req_ping);
                s.Send(this.icmp_req_time);

                count++;

                if (verbose && (count % 1000 == 0 || count == Addresses.Length))
                {
                    BlumUtils.ClearCurrentConsoleLine();
                    Console.Write("BlUM> Sent {0} out of {1} packets so far...", count, Addresses.Length);
                }
                if (count % BlumValues.PacketCountCooldown == 0) Thread.Sleep(BlumValues.PacketCooldown);
                
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            // Dev Args
            // string argStr = "-i 5 -oN test.txt 91.92.194.0-91.92.194.255";
            // args = argStr.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

            BlumArguments BlumArgs = new BlumArguments(args);

            /*
            Console.WriteLine("Command  : {0}", BlumArgs.Command);
            Console.WriteLine("Interface: {0}", BlumArgs.InterfaceIndex);
            Console.WriteLine("Output   : {0}", BlumArgs.OutputFilePath);
            Console.WriteLine("Start    : {0}", BlumArgs.StartIPAddress);
            Console.WriteLine("End      : {0}", BlumArgs.EndIPAddress);
            */

            if (BlumArgs.Command == BlumCommand.Error) { Console.WriteLine(BlumStrings.ResolvingError); return; }
            if (BlumArgs.Command == BlumCommand.Help) { Console.WriteLine(BlumStrings.Help); return; }
            if (BlumArgs.Command == BlumCommand.Interfaces)
            {
                LibPcapLiveDeviceList libs = LibPcapLiveDeviceList.Instance;
                Console.WriteLine("BlUM> INTERFACES:\r\n");
                for (int i = 0; i < libs.Count; i++) Console.WriteLine("<{0}> Interface: {1}, IP Address: {2}", i, libs[i].Interface.FriendlyName, libs[i].Addresses.Count < 2 ? "None" : libs[i].Addresses[1].Addr.ipAddress.ToString());
                return;
            }

            if (BlumArgs.Command == BlumCommand.Scan)
            {
                if (!BlumUtils.IsAdmin()) { Console.WriteLine(BlumStrings.AdminNotice); return; }

                LibPcapLiveDeviceList libs = LibPcapLiveDeviceList.Instance;

                ICaptureDevice device;
                bool ValidDevice = BlumArgs.PickUpInterface(libs, out device);

                if (!ValidDevice && BlumArgs.InterfaceIndex == -1) { Console.WriteLine(BlumStrings.NoValidInterface); return; }
                if (!ValidDevice) { Console.WriteLine(BlumStrings.InvalidInterface); return; }

                IPAddressRange Range = new IPAddressRange(BlumArgs.StartIPAddress, BlumArgs.EndIPAddress);

                Console.WriteLine("BlUM> Preparing to scan range {0} to {1}...", new IPAddress(Range.lowerBytes), new IPAddress(Range.upperBytes));

                BlumPacketAnalyzer analyzer = new BlumPacketAnalyzer(Range, device);

                analyzer.Listen();

                Thread.Sleep(BlumValues.WaitAnalyzer);

                Console.WriteLine("BlUM> Starting packet sending!");

                BlumPacketSender sender = new BlumPacketSender(Range);

                sender.Send(true);

                Console.WriteLine("\nBlUM> Packet sending finished! Preparing results...");

                Thread.Sleep(BlumValues.TimeOut);

                int hosts = analyzer.Data.HostsUp.Length;
                Console.WriteLine("BlUM> A total of {0} hosts up found:", hosts);

                string[] HostStrings = new string[hosts];
                for (int i = 0; i < hosts; i++)
                {
                    Console.WriteLine("BlUM> {0}", analyzer.Data.HostsUp[i]);
                    HostStrings[i] = analyzer.Data.HostsUp[i].ToString();
                }

                if (BlumArgs.OutputFile) File.WriteAllLines(BlumArgs.OutputFilePath, HostStrings);

                analyzer.Stop();

                Environment.Exit(0);

                
            }

        }
    }
}
