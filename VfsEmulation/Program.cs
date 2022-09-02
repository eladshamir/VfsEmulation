using DiscUtils;
using DiscUtils.Fat;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.IO.Compression;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace VfsEmulation
{
    internal class Program
    {
        [Flags]
        public enum EFileAccess : uint
        {
            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000
        }

        [Flags]
        public enum EFileShare : uint
        {
            None = 0x00000000,
            Read = 0x00000001,
            Write = 0x00000002,
            Delete = 0x00000004
        }

        public enum ECreationDisposition : uint
        {
            New = 1,
            CreateAlways = 2,
            OpenExisting = 3,
            OpenAlways = 4,
            TruncateExisting = 5
        }

        [Flags]
        public enum EFileAttributes : uint
        {
            Normal = 0x00000080
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern SafeFileHandle CreateFile(
           string lpFileName,
           EFileAccess dwDesiredAccess,
           EFileShare dwShareMode,
           IntPtr lpSecurityAttributes,
           ECreationDisposition dwCreationDisposition,
           EFileAttributes dwFlagsAndAttributes,
           IntPtr hTemplateFile);

        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(data, encryptor);
                }
            }
        }

        public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(data, decryptor);
                }
            }
        }

        private static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }

        static byte[] CreateFATFileSystem(string label, long capacity)
        {
            Geometry geometry = Geometry.FromCapacity(capacity);
            MemoryStream ms = new MemoryStream();
            FatFileSystem vfs = FatFileSystem.FormatPartition(ms, label, geometry, 0, (int)geometry.TotalSectorsLong, 0);
            return ms.ToArray();
        }

        static bool GetKey(string keypath, out byte[] key, out byte[] iv, bool ads)
        {
            if (ads)
            {
                return GetKeyFromADS(keypath, out key, out iv);
            }
            else
            {
                return GetKeyFromRegistry(keypath, out key, out iv);
            }    
        }

        static bool GetKeyFromADS(string keypath, out byte[] key, out byte[] iv)
        {
            key = new byte[32];
            iv = new byte[16];
            byte[] b = new byte[48];

            string fileName = keypath.Substring(0, keypath.LastIndexOf(':'));
            string streamName = keypath.Substring(keypath.LastIndexOf(':') + 1);

            var sfh = CreateFile(keypath,
                    EFileAccess.GenericRead | EFileAccess.GenericWrite,
                    EFileShare.Read,
                    IntPtr.Zero,
                    ECreationDisposition.OpenExisting,
                    EFileAttributes.Normal,
                    IntPtr.Zero);
            if (sfh.IsInvalid)
            {
                Console.WriteLine("[!] Could not fine alternative data stream {0}{1}[*] Generating new key", keypath, Environment.NewLine);

                var rnd = new RNGCryptoServiceProvider();
                rnd.GetNonZeroBytes(b);

                sfh = CreateFile(keypath,
                    EFileAccess.GenericRead | EFileAccess.GenericWrite,
                    EFileShare.Read,
                    IntPtr.Zero,
                    ECreationDisposition.CreateAlways,
                    EFileAttributes.Normal,
                    IntPtr.Zero);
                if (sfh.IsInvalid)
                {
                    throw new Exception(String.Format("Failed to create file {0}", keypath));
                }

                using (FileStream fs = new FileStream(sfh, FileAccess.Write))
                {
                    fs.Write(b, 0, b.Length);
                }

                sfh.Close();
            }
            else
            {
                using (FileStream fs = new FileStream(sfh, FileAccess.Read))
                {
                    fs.Read(b, 0, b.Length);
                }
                sfh.Close();
                Console.WriteLine("[+] Retrieved the key from alternative data stream {0}", keypath);
            }

            Array.Copy(b, 0, key, 0, 32);
            Array.Copy(b, 32, iv, 0, 16);

            return true;
        }

        static bool GetKeyFromRegistry(string keypath, out byte[] key, out byte[] iv)
        {
            key = new byte[32];
            iv = new byte[16];
            byte[] b = new byte[48];

            string keyName = keypath.Substring(0, keypath.LastIndexOf('\\'));
            string valueName = keypath.Substring(keypath.LastIndexOf('\\') + 1);

            RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(keyName, true);
            object value = null;
            if (registryKey == null)
            {
                Console.WriteLine("[!] Could not open Registry key {0}", keyName);
                return false;
            }

            value = registryKey.GetValue(valueName);
            if (value == null)
            {
                var rnd = new RNGCryptoServiceProvider();
                rnd.GetNonZeroBytes(b);
                registryKey.SetValue(valueName, b, RegistryValueKind.Binary);
                Console.WriteLine("[+] Generated a new key");
            }
            else
            {
                b = (byte[])value;
                Console.WriteLine("[+] Retrieved the key from Registry");
            }

            Array.Copy(b, 0, key, 0, 32);
            Array.Copy(b, 32, iv, 0, 16);

            return true;
        }

        static byte[] Compress(byte[] data)
        {
            using (var compressedStream = new MemoryStream())
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Compress))
            {
                zipStream.Write(data, 0, data.Length);
                zipStream.Close();
                return compressedStream.ToArray();
            }
        }

        static byte[] Decompress(byte[] data)
        {
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {
                zipStream.CopyTo(resultStream);
                return resultStream.ToArray();
            }
        }

        static void InitializeVFS(string filepath, string keypath, string label, long capacity, bool ads)
        {
            try
            {
                Console.WriteLine("[*] Creating a new FAT VFS");
                byte[] vfsBytes = CreateFATFileSystem(label, capacity);
                if (vfsBytes == null)
                {
                    Console.WriteLine("[X] Failed to create VFS");
                    return;
                }
                Console.WriteLine("[+] VFS Created");

                SaveVFStoDisk(vfsBytes, filepath, keypath, ads);
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("Failed to initialize VFS: {0}", ex.Message));
            }
        }

        static void SaveVFStoDisk(byte[] bytes, string filepath, string keypath, bool ads, bool hidden = true, bool compress = true)
        {
            try
            {
                // Compress the VFS before encrypting it
                if (compress)
                {
                    Console.WriteLine("[*] Compressing the data");
                    bytes = Compress(bytes);
                }

                // Obtain key from Registry or generate a new one
                Console.WriteLine("[*] Obtaining an encryption key");
                byte[] key;
                byte[] iv;
                GetKey(keypath, out key, out iv, ads);

                // Encrypt the VFS
                Console.WriteLine("[*] Encrypting the VFS");
                byte[] encryptedVfsBytes = Encrypt(bytes, key, iv);

                // Write the encrypted VFS to disk
                Console.WriteLine("[*] Writing VFS to {0}", filepath);
                using (FileStream fs = new FileStream(filepath, FileMode.OpenOrCreate))
                {
                    fs.Write(encryptedVfsBytes, 0, encryptedVfsBytes.Length);
                }
                if (hidden)
                {
                    File.SetAttributes(filepath, File.GetAttributes(filepath) | FileAttributes.Hidden);
                }
                Console.WriteLine("[+] Successfully wrote VFS to {0}", filepath);
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("Failed to save VFS: {0}", ex.Message));
            }
        }

        static void SaveVFStoDisk(MemoryStream stream, string filepath, string keypath, bool hidden = true, bool compress = true)
        {
            SaveVFStoDisk(stream.ToArray(), filepath, keypath, hidden, compress);
        }

        static FatFileSystem OpenVFS(MemoryStream stream, string filepath, string keypath, bool ads, bool compress = true)
        {
            try
            {
                Console.WriteLine("[*] Opening an existing VFS");

                // Obtain key from Registry or generate a new one
                Console.WriteLine("[*] Obtaining the decryption key");
                byte[] key;
                byte[] iv;
                GetKey(keypath, out key, out iv, ads);

                // Read encrypted VFS from disk
                Console.WriteLine("[*] Reading VFS from {0}", filepath);
                byte[] encryptedVfsBytes = File.ReadAllBytes(filepath);

                // Decrypt the VFS
                Console.WriteLine("[*] Decrypting the VFS");
                byte[] vfsBytes = Decrypt(encryptedVfsBytes, key, iv);

                // Load the VFS
                Console.WriteLine("[*] Loading the VFS");

                // Decompress the VFS before decrypting it
                if (compress)
                {
                    vfsBytes = Decompress(vfsBytes);
                }

                stream.Write(vfsBytes, 0, vfsBytes.Length);

                // Construct the VFS
                FatFileSystem fatFileSystem = new FatFileSystem(stream);

                if (fatFileSystem == null)
                {
                    Console.WriteLine("[X] Could not load VFS");
                }
                else
                {
                    Console.WriteLine("[+] VFS successfully loaded");
                }
                return fatFileSystem;
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("Failed to open VFS: {0}", ex.Message));
            }

        }

        static string prefix(int length)
        {
            string res = "";
            for (int i = 0; i < length; i++)
            {
                res += "|";
            }
            return res;
        }

        static string ExtractName(string path)
        {
            return path.Substring(path.LastIndexOf('\\') + 1);
        }

        static void ListDirectory(FatFileSystem vfs, string path, int level=0)
        {
            Console.WriteLine("{1}+{0}", ExtractName(path), prefix(level));
            foreach(string directory in vfs.GetDirectories(path))
            {
                ListDirectory(vfs, directory, level + 1);
            }

            foreach (string file in vfs.GetFiles(path))
            {
                Console.WriteLine("{1}|{0}", ExtractName(file), prefix(level));
            }
        }

        static void PrintHelp()
        {
            string usage = @"
  This project is a basic implementation of an AES256-encrypted virtual FAT file system for emulating TTPs 
  used by certain groups.
  
  The encryption key is store in Registry in a user-specified key under HKCU.

  Usage: VfsEmulation.exe <command> /filepath:<path to VFS file> /keypath:<Registry path for encryption key> [/ads]
  </additional command-specific arguments>

  The /ads flag instructs the program to load/save the key to a file/alternative data stream instead of the Registry

  Commands
    init            Create a new virtual file system and write it to file
        Optional Arguments:
            /capacity:    The capacity of the virtual partition in bytes
            /label:       The label of the partition
        Examples:
            VfsEmulation.exe init /filepath:iecache.bin /keypath:""SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\Order"" /capacity:8634368 /label:VFS
            VfsEmulation.exe init /filepath:iecache.bin /ads /keypath:""%TEMP%\KB943729.log:{1DC12691-2B24-2265-435D-735D3B118A70}"" /capacity:8634368 /label:VFS

    mkdir           Create a new directory
        Required Arguments:
            /targetpath:  The name of the new directory (full path, e.g., loot\documents)
        Examples:
            VfsEmulation.exe mkdir /filepath:iecache.bin /keypath:""SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\Order"" /targetpath:loot
            VfsEmulation.exe mkdir /filepath:iecache.bin /ads /keypath:""%TEMP%\KB943729.log:{1DC12691-2B24-2265-435D-735D3B118A70}"" /targetpath:loot

    add             Add a file to the VFS
        Required Arguments:
            /targetpath:  The path of the new file on the VFS
            /sourcefile:  Either a Base64-encoded blob or the path of the file to be add
        Examples:
            VfsEmulation.exe add /filepath:iecache.bin /keypath:""SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\Order"" /targetpath:loot\credentials\passwords.txt /sourcefile:C:\Users\Administrator\Desktop\passwords.txt
            VfsEmulation.exe add /filepath:iecache.bin /ads /keypath:""%TEMP%\KB943729.log:{1DC12691-2B24-2265-435D-735D3B118A70}"" /targetpath:loot\credentials\passwords.txt /sourcefile:C:\Users\Administrator\Desktop\passwords.txt

    removefile      Remove a file from the VFS
        Required Arguments:
            /targetpath:  The path of the file to remove
        Examples:
            VfsEmulation.exe removefile /filepath:iecache.bin /keypath:""SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\Order"" /targetpath:loot\credentials\passwords.txt
            VfsEmulation.exe removefile /filepath:iecache.bin /ads /keypath:""%TEMP%\KB943729.log:{1DC12691-2B24-2265-435D-735D3B118A70}"" /targetpath:loot\credentials\passwords.txt

    removedir      Remove a directory from the VFS
        Required Arguments:
            /targetpath:  The path of the directory to remove
        Examples:
            VfsEmulation.exe removefile /filepath:iecache.bin /keypath:""SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\Order"" /targetpath:loot\credentials
            VfsEmulation.exe removefile /filepath:iecache.bin /ads /keypath:""%TEMP%\KB943729.log:{1DC12691-2B24-2265-435D-735D3B118A70}"" /targetpath:loot\credentials

    open            Retrieve a file from the VFS
        Required Arguments:
            /targetpath:  The path of the file to retrieve
        Optional Arguments:
            /outfile:     The path where the file will be saved
            If outfile is note provided, the file will be printed to stdout as a Base64-encoded blob
        Examples:
            VfsEmulation.exe open /filepath:iecache.bin /keypath:""SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\Order"" /targetpath:loot\credentials\passwords.txt
            VfsEmulation.exe open /filepath:iecache.bin /ads /keypath:""%TEMP%\KB943729.log:{1DC12691-2B24-2265-435D-735D3B118A70}"" /targetpath:loot\credentials\passwords.txt
    
    list            List the contents of a directory
        Required Arguments:
            /targetpath:  The path of the direcotry to list
        Examples:
            VfsEmulation.exe list /filepath:iecache.bin /keypath:""SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\Order"" /targetpath:loot\credentials
            VfsEmulation.exe list /filepath:iecache.bin /ads /keypath:""%TEMP%\KB943729.log:{1DC12691-2B24-2265-435D-735D3B118A70}"" /targetpath:loot\credentials

";
            Console.WriteLine(usage);
        }

        static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        static void Main(string[] args)
        {
            try { 
                // Parse command line
                string command = null;
                if (args.Length > 0)
                {
                    command = args[0].ToLower();
                }

                if (String.IsNullOrEmpty(command) || !(command.Equals("init") || (command.Equals("mkdir") || command.Equals("add") || command.Equals("removefile") || command.Equals("removedir") || command.Equals("open") || command.Equals("list"))))
                {
                    throw new Exception("No command was provided");
                }

                var arguments = new Dictionary<string, string>();
                for (int i = 1; i < args.Length; i++)
                {
                    string argument = args[i];
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                    {
                        arguments[argument.Substring(1, idx - 1).ToLower()] = argument.Substring(idx + 1);
                    }
                    else
                    {
                        idx = argument.IndexOf('=');
                        if (idx > 0)
                        {
                            arguments[argument.Substring(1, idx - 1).ToLower()] = argument.Substring(idx + 1);
                        }
                        else
                        {
                            arguments[argument.Substring(1).ToLower()] = string.Empty;
                        }
                    }
                }

                string filepath;
                string keypath;
                long capacity;
                long minCapacity = 4317184;
                string targetpath;
                string sourcefile;
                string outfile = null;
                string label = "";
                bool ads = false;
                MemoryStream stream = new MemoryStream();

                if (!arguments.ContainsKey("filepath") || String.IsNullOrEmpty(arguments["filepath"]))
                {
                    throw new Exception("/filepath is required and must contain the path of the encrypted VFS file.\r\n");
                }
                else
                {
                    filepath = arguments["filepath"];
                }

                if (!arguments.ContainsKey("keypath") || String.IsNullOrEmpty(arguments["keypath"]))
                {
                    throw new Exception("/keypath is required and must contain the Registry path of the encryption keys.\r\n");
                }
                else
                {
                    keypath = arguments["keypath"];
                }
                if (arguments.ContainsKey("ads"))
                {
                    ads = true;
                }

                // Initialize a new VFS
                if (command.Equals("init"))
                {
                    if (!arguments.ContainsKey("capacity") || String.IsNullOrEmpty(arguments["capacity"]))
                    {
                        capacity = minCapacity;
                    }
                    else 
                    { 
                        if (!long.TryParse(arguments["capacity"], out capacity))
                        {
                            throw new Exception("No valid capacity was provided for /capacity");
                        }

                        if (capacity < minCapacity)
                        {
                            capacity = minCapacity;
                        }
                    }

                    if (arguments.ContainsKey("label") && !String.IsNullOrEmpty(arguments["label"]))
                    {
                        label = arguments["label"];
                    }

                    Console.WriteLine("[*] Initializing a new VFS");
                    InitializeVFS(filepath, keypath, label, capacity, ads);
                    Console.WriteLine("[+] VFS successfully initialized");
                }

                // Create a new directory
                else if (command.Equals("mkdir"))
                {
                    if (!arguments.ContainsKey("targetpath") || String.IsNullOrEmpty(arguments["targetpath"]))
                    { 
                        throw new Exception("/targetpath is required and must contain the path of the new directory.\r\n");
                    }
                    else
                    {
                        targetpath = arguments["targetpath"];
                        FatFileSystem vfs = OpenVFS(stream, filepath, keypath, ads);
                        Console.WriteLine("[*] Creating the new directory: {0}", targetpath);
                        vfs.CreateDirectory(targetpath);
                        Console.WriteLine("[+] Directory successfully created: {0}", targetpath);
                        SaveVFStoDisk(stream.ToArray(), filepath, keypath, ads);
                    }
                }

                // Add a file to the VFS
                else if (command.Equals("add"))
                {
                    if (!arguments.ContainsKey("targetpath") || String.IsNullOrEmpty(arguments["targetpath"]))
                    {
                        throw new Exception("/targetpath is required and must contain the path of the new file in the VFS.\r\n");
                    }
                    else
                    {
                        targetpath = arguments["targetpath"];
                    }

                    if (!arguments.ContainsKey("sourcefile") || String.IsNullOrEmpty(arguments["sourcefile"]))
                    {
                        throw new Exception("/sourcefile is required and must contain the new file to be added to the VFS as a filepath or a Base64 encoded blob.\r\n");
                    }
                    else
                    {
                        sourcefile = arguments["sourcefile"];
                        byte[] sourcebytes;
                        if (IsBase64String(sourcefile))
                        {
                            sourcebytes = Convert.FromBase64String(sourcefile);
                        }
                        else if (File.Exists(sourcefile))
                        {
                            sourcebytes = File.ReadAllBytes(sourcefile);
                        }
                        else
                        {
                            throw new Exception("Failed to open source file");
                        }

                        FatFileSystem vfs = OpenVFS(stream, filepath, keypath, ads);
                        Console.WriteLine("[*] Adding file to VFS");
                        using (Stream s = vfs.OpenFile(targetpath, FileMode.Create))
                        {
                            s.Write(sourcebytes, 0, sourcebytes.Length);
                        }
                        Console.WriteLine("[+] File successfully written to {0}", targetpath);
                        SaveVFStoDisk(stream.ToArray(), filepath, keypath, ads);                       
                    }
                }

                // Remove a file from the VFS
                else if (command.Equals("removefile"))
                {
                    if (!arguments.ContainsKey("targetpath") || String.IsNullOrEmpty(arguments["targetpath"]))
                    {
                        throw new Exception("/targetpath is required and must contain the path of the file in the VFS.\r\n");
                    }
                    else
                    {
                        targetpath = arguments["targetpath"];
                    }

                    FatFileSystem vfs = OpenVFS(stream, filepath, keypath, ads);
                    Console.WriteLine("[*] Removing file from VFS");
                    vfs.DeleteFile(targetpath);
                    Console.WriteLine("[+] File successfully removed: {0}", targetpath);
                    SaveVFStoDisk(stream.ToArray(), filepath, keypath, ads );
                }

                // Remove a directory from the VFS
                else if (command.Equals("removedir"))
                {
                    if (!arguments.ContainsKey("targetpath") || String.IsNullOrEmpty(arguments["targetpath"]))
                    {
                        throw new Exception("/targetpath is required and must contain the path of directory in the VFS.\r\n");
                    }
                    else
                    {
                        targetpath = arguments["targetpath"];
                    }

                    FatFileSystem vfs = OpenVFS(stream, filepath, keypath, ads);
                    Console.WriteLine("[*] Removing directory from VFS");
                    vfs.DeleteDirectory(targetpath);
                    Console.WriteLine("[+] Directory successfully removed: {0}", targetpath);
                    SaveVFStoDisk(stream.ToArray(), filepath, keypath, ads);
                }

                // Open a file from the VFS
                else if (command.Equals("open"))
                {
                    if (!arguments.ContainsKey("targetpath") || String.IsNullOrEmpty(arguments["targetpath"]))
                    {
                        throw new Exception("/targetpath is required and must contain the path of the file in the VFS.\r\n");
                    }
                    else
                    {
                        targetpath = arguments["targetpath"];
                    }

                    if (arguments.ContainsKey("outfile") && !String.IsNullOrEmpty(arguments["outfile"]))
                    {
                        outfile = arguments["outfile"];
                    }

                    FatFileSystem vfs = OpenVFS(stream, filepath, keypath, ads);
                    MemoryStream ms = new MemoryStream();
                    using (Stream s = vfs.OpenFile(targetpath, FileMode.Open))
                    {
                        using (StreamReader reader = new StreamReader(s))
                        {
                            int bytesRead;
                            byte[] buffer = new byte[512];
                            while ((bytesRead = reader.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                ms.Write(buffer, 0, bytesRead);
                            }
                        }
                    }

                    if (!string.IsNullOrEmpty(outfile))
                    {
                        File.WriteAllBytes(outfile, ms.ToArray());
                        Console.WriteLine("[+] The file was saved to {0}", outfile);
                    }
                    else
                    {
                        Console.WriteLine("[+] Retrieved the file {0}:{1}{2}", targetpath, Environment.NewLine, Convert.ToBase64String(ms.ToArray()));
                    }
                }

                // List a directory from the VFS
                else if (command.Equals("list"))
                {
                    if (!arguments.ContainsKey("targetpath") || String.IsNullOrEmpty(arguments["targetpath"]))
                    {
                        throw new Exception("/targetpath is required and must contain the path of directory in the VFS.\r\n");
                    }
                    else
                    {
                        targetpath = arguments["targetpath"];
                    }

                    FatFileSystem vfs = OpenVFS(stream, filepath, keypath, ads);
                    Console.WriteLine("[*] Listing directory {0}:", targetpath);
                    ListDirectory(vfs, targetpath);
                }
            }
            catch (Exception ex)
            {
                PrintHelp();
                Console.WriteLine("[X] {0}", ex.Message);
            }
        }
    }
}
