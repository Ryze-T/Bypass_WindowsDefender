using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace shellcodeEncrypt
{
    internal class Program
    {
        static string ReadShellCode(string filePath)
        {
            string base64Str = string.Empty;
            FileStream fileStream = new FileStream(filePath, FileMode.Open);
            try
            {
                byte[] bt = new byte[fileStream.Length];

                //调用read读取方法
                fileStream.Read(bt, 0, bt.Length);
                base64Str = Convert.ToBase64String(bt);
                fileStream.Close();
                Console.WriteLine("[*] Reading Shellcode...");
                return base64Str;
            }
            catch (IOException e)
            {
                Console.WriteLine("[-] {0}",e.Message.ToString());
                return null;
            }
        }
        static string Generate_Key()
        {
            string chars = "0123456789ABCDEFGHIJKLMNOPQSTUVWXYZabcdefghijklmnpqrstuvwxyz";
            string return_key = String.Empty;
            Random random = new Random();
            for (int i = 0; i < 32; i++)
            {
                return_key += chars[random.Next(chars.Length)];
            }
            Console.WriteLine("[+] Generate Key is \n{0}",return_key);
            return return_key;
        }
        /// <summary>
        /// AES 算法加密(ECB模式) 将明文加密，加密后进行base64编码，返回密文
        /// </summary>
        /// <param name="EncryptStr">明文</param>
        /// <param name="Key">密钥</param>
        /// <returns>加密后base64编码的密文</returns>
        public static string AesEncryptor_Base64(string EncryptStr)
        {
            try
            {
                string Key = Generate_Key();
                //byte[] keyArray = Encoding.UTF8.GetBytes(Key);
                byte[] keyArray = Convert.FromBase64String(Key);
                byte[] toEncryptArray = Encoding.UTF8.GetBytes(EncryptStr);

                RijndaelManaged rDel = new RijndaelManaged();
                rDel.Key = keyArray;
                rDel.Mode = CipherMode.ECB;
                rDel.Padding = PaddingMode.PKCS7;

                ICryptoTransform cTransform = rDel.CreateEncryptor();
                byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

                return Convert.ToBase64String(resultArray, 0, resultArray.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] {0}",ex.Message.ToString());
                return null;
            }
        }
        static void Main(string[] args)
        {
            if(args.Length != 1)
            {
                Console.WriteLine("[*] Usage: shellcodeEncrypt shellcodeFilePath");
                return ;
            }
            String shellcode = ReadShellCode(args[0]);
            Console.WriteLine("[+] Get shellcode successful");
            String EncryptString = AesEncryptor_Base64(shellcode);
            Console.WriteLine("[+] Encrypted Shellcode is \n{0}",EncryptString);
        }
    }
}
