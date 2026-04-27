using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using System.IdentityModel.Tokens.Jwt;

namespace TokenLogin
{

    class SteamID
    {
        public int X { get; private set; }
        public int Y { get; private set; }
        public int Z { get; private set; }

        public SteamID(string anySteamid)
        {
            Convert(anySteamid);
        }

        public long GetSteam64Id()
        {
            return GetSteam32Id() + 76561197960265728;
        }

        public int GetSteam32Id()
        {
            return 2 * Z + Y;
        }

        public string GetSteamId3()
        {
            return $"U:{Y}:{GetSteam32Id()}";
        }

        public string GetSteamId()
        {
            return $"STEAM_{X}:{Y}:{Z}";
        }

        private void Convert(string anySteamid)
        {
            anySteamid = anySteamid.ToLower().Replace(" ", "");

            long steamid = long.Parse(anySteamid);
            long steam32Id;

            if (steamid > 76561197960265728)
                steam32Id = steamid - 76561197960265728;
            else
                steam32Id = steamid;

            X = 0;
            Y = (steam32Id % 2 == 0) ? 0 : 1;
            Z = (int)((steam32Id - Y) / 2);
        }
    }

    class Program
    {
        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptProtectData(ref DATA_BLOB pDataIn,string szDataDescr,ref DATA_BLOB pOptionalEntropy,IntPtr pvReserved,IntPtr pPromptStruct,int dwFlags,out DATA_BLOB pDataOut);

        [StructLayout(LayoutKind.Sequential)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        static string FindSteam()
        {
            return (string)Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam")?.GetValue("SteamPath");
        }

        static JwtSecurityToken DecodeToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(token);
            return jsonToken;
        }

        static void KillSteam()
        {
            string[] processes = { "Steam", "steamwebhelper", "steamservice" };

            foreach (var name in processes)
                foreach (var p in Process.GetProcessesByName(name))
                    p.Kill();
        }

        static string CryptProtectData(byte[] data, byte[] optionalEntropy)
        {
            DATA_BLOB dataIn = new DATA_BLOB();
            DATA_BLOB entropyIn = new DATA_BLOB();
            DATA_BLOB dataOut = new DATA_BLOB();

            dataIn.cbData = data.Length;
            dataIn.pbData = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, dataIn.pbData, data.Length);

            entropyIn.cbData = optionalEntropy.Length;
            entropyIn.pbData = Marshal.AllocHGlobal(optionalEntropy.Length);
            Marshal.Copy(optionalEntropy, 0, entropyIn.pbData, optionalEntropy.Length);

            CryptProtectData(ref dataIn, null, ref entropyIn, IntPtr.Zero, IntPtr.Zero, 0, out dataOut);

            byte[] result = new byte[dataOut.cbData];
            Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
            Marshal.FreeHGlobal(dataOut.pbData);
            Marshal.FreeHGlobal(dataIn.pbData);
            Marshal.FreeHGlobal(entropyIn.pbData);

            return BitConverter.ToString(result).Replace("-", "").ToLower();
        }

        static void Main()
        {
            Console.Write("Enter token: ");
            string token = Console.ReadLine().Trim();

            int firstDotIndex = token.IndexOf('.');
            string login = token.Substring(0, firstDotIndex);
            string tokenPart = token.Substring(firstDotIndex + 1);
            string steamdir = FindSteam();

            KillSteam();

            var jwtToken = DecodeToken(tokenPart);
            string steamid = jwtToken.Payload.Sub ?? jwtToken.Claims.First(c => c.Type == "sub").Value;

            var steamIdObj = new SteamID(steamid);

            string userdataDir = Path.Combine(steamdir, "userdata", steamIdObj.GetSteam32Id().ToString(), "config");
            Directory.CreateDirectory(userdataDir);

            File.WriteAllText(Path.Combine(userdataDir, "localconfig.vdf"),"\"UserLocalConfigStore\"\n{\n    \"streaming_v2\"\n    {\n        \"EnableStreaming\"       \"0\"\n    }\n    \"friends\"\n    {\n        \"SignIntoFriends\"      \"0\"\n    }\n}\n",Encoding.UTF8);

            string configDir = Path.Combine(steamdir, "config");
            Directory.CreateDirectory(configDir);

            File.WriteAllText(Path.Combine(configDir, "config.vdf"),$"\"InstallConfigStore\"\n{{\n    \"Software\"\n    {{\n        \"Valve\"\n        {{\n            \"Steam\"\n            {{\n                \"Accounts\"\n                {{\n                    \"{login}\"\n                    {{\n                        \"SteamID\"\t\t\"{steamid}\"\n                    }}\n                }}\n            }}\n        }}\n    }}\n}}\n",Encoding.UTF8);
            File.WriteAllText(Path.Combine(configDir, "loginusers.vdf"),$"\"users\"\n{{\n    \"{steamid}\"\n    {{\n        \"AccountName\"\t\t\"{login}\"\n        \"PersonaName\"\t\t\"{login}\"\n        \"RememberPassword\"\t\t\"1\"\n        \"WantsOfflineMode\"\t\t\"0\"\n        \"SkipOfflineModeWarning\"\t\t\"0\"\n        \"AllowAutoLogin\"\t\t\"0\"\n        \"MostRecent\"\t\t\"1\"\n        \"Timestamp\"\t\t\"{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}\"\n    }}\n}}\n",Encoding.UTF8);
            string localAppDataSteam = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Steam");
            Directory.CreateDirectory(localAppDataSteam);
            string hdr = CryptProtectData(Encoding.UTF8.GetBytes(tokenPart),Encoding.UTF8.GetBytes(login));
            File.WriteAllText(Path.Combine(localAppDataSteam, "local.vdf"),$"\"MachineUserConfigStore\"\n{{\n    \"Software\"\n    {{\n        \"Valve\"\n        {{\n            \"Steam\"\n            {{\n                \"ConnectCache\"\n                {{\n                    \"{hdr}\"\t\t\"{hdr}\"\n                }}\n            }}\n        }}\n    }}\n}}\n",Encoding.UTF8);
            Process.Start(new ProcessStartInfo("cmd", "/c start steam://0") { CreateNoWindow = true, UseShellExecute = false });

            Console.WriteLine("Done.");
            Console.WriteLine("Press Enter to exit...");
            Console.ReadLine();
        }
    }
}
