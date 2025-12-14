using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Path = System.IO.Path;

namespace NautilusFREE
{
    public class nTools
    {
        #region Declarations
                        
        // Struct which contains information that the SHFileOperation function uses to perform file operations.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SHFILEOPSTRUCT
        {
            public IntPtr hwnd;
            [MarshalAs(UnmanagedType.U4)]
            public int wFunc;
            public string pFrom;
            public string pTo;
            public short fFlags;
            [MarshalAs(UnmanagedType.Bool)]
            public bool fAnyOperationsAborted;
            public IntPtr hNameMappings;
            public string lpszProgressTitle;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        static extern int SHFileOperation(ref SHFILEOPSTRUCT FileOp);
        #endregion
         
        /// <summary>
        /// Simple function to safely delete files
        /// </summary>
        /// <param name="file">Full path of file to be deleted</param>
        public void DeleteFile(string file)
        {
            if (string.IsNullOrWhiteSpace(file)) return;
            if (!File.Exists(file)) return;
            try
            {
                File.Delete(file);
            }
            catch (Exception)
            {}
        }

        public bool EncSave(string fileIn, string fileOut)
        {
            var Crypto = new MoggFile();
            return Crypto.Encrypt(File.ReadAllBytes(fileIn), fileOut);
        }

        public bool DecSave(string fileIn, string fileOut)
        {                      
            var Crypto = new MoggFile();
            return Crypto.Decrypt(File.ReadAllBytes(fileIn), true, true, DecryptMode.ToFile, fileOut);
        }

        #region Mogg Stuff               

        private GCHandle PlayingOggStreamHandle;
        private GCHandle NextOggStreamHandle;
        public byte[] PlayingSongOggData;
        public byte[] NextSongOggData;

        public void ReleaseStreamHandle(bool isNext = false)
        {
            try
            {
                if (isNext)
                {
                    NextOggStreamHandle.Free();
                }
                else
                {
                    PlayingOggStreamHandle.Free();
                }
            }
            catch (Exception)
            { }
        }

        public IntPtr GetOggStreamIntPtr(bool isNext = false)
        {
            ReleaseStreamHandle(isNext);
            if (isNext)
            {
                NextOggStreamHandle = GCHandle.Alloc(NextSongOggData, GCHandleType.Pinned);
                return NextOggStreamHandle.AddrOfPinnedObject();
            }
            PlayingOggStreamHandle = GCHandle.Alloc(PlayingSongOggData, GCHandleType.Pinned);
            return PlayingOggStreamHandle.AddrOfPinnedObject();
        }                

        public bool EncM(byte[] mData, string mOut)
        {
            if (IsC3Mogg(mData)) //remove old encryption
            {
                var tempM = Path.GetTempPath() + "m";
                if (DecM(mData, true, false, DecryptMode.ToFile, tempM))
                {
                    mData = File.ReadAllBytes(tempM);
                    DeleteFile(tempM);
                }
            }
            if (MoggIsEncrypted(mData)) return true;
            var Crypto = new MoggFile();
            return Crypto.Encrypt(mData, mOut);
        }

        public bool PatchMoggForPS3Use(string mOut)
        {
            byte[] NEW_PS3_MASK = new byte[] { 0xA5, 0xCE, 0xFD, 0x06, 0x11, 0x93, 0x23, 0x21, 0xF8, 0x87, 0x85, 0xEA, 0x95, 0xE4, 0x94, 0xD4 };
            byte[] LOCALH_MASK = new byte[] { 0xF1, 0xB4, 0xB8, 0xB0, 0x48, 0xAF, 0xCB, 0x9B, 0x4B, 0x53, 0xE0, 0x56, 0x64, 0x57, 0x68, 0x39 };
            var isv12 = false;

            var patched = false;
            if (File.Exists(mOut))
            {
                var mData = File.ReadAllBytes(mOut);
                isv12 = mData[0] == 0x0C;
                var offset = 0;                
                using (var ms = new MemoryStream(mData))
                {
                    using (var br = new BinaryReader(ms))
                    {
                        br.BaseStream.Position = 16;
                        int headerBufferSize = br.ReadInt32();
                        offset = 20 + (headerBufferSize * 8) + 16 + 16;
                    }
                }
                using (var ms = new MemoryStream(mData))
                {
                    using (var bw = new BinaryWriter(ms))
                    {
                        bw.BaseStream.Seek(offset, SeekOrigin.Begin);
                        bw.Write(isv12? LOCALH_MASK : NEW_PS3_MASK);
                        patched = true;
                    }
                }
                if (patched)
                {
                    File.WriteAllBytes(mOut, mData);
                }
            }
            return File.Exists(mOut) && patched;
        }

        public bool MoggIsAlreadyPatched(byte[] mData)
        {
            byte[] NEW_PS3_MASK = new byte[] { 0xA5, 0xCE, 0xFD, 0x06, 0x11, 0x93, 0x23, 0x21, 0xF8, 0x87, 0x85, 0xEA, 0x95, 0xE4, 0x94, 0xD4 };
            byte[] LOCALH_MASK = new byte[] { 0xF1, 0xB4, 0xB8, 0xB0, 0x48, 0xAF, 0xCB, 0x9B, 0x4B, 0x53, 0xE0, 0x56, 0x64, 0x57, 0x68, 0x39 };

            var patched = false;
            var offset = 0;
            using (var ms = new MemoryStream(mData))
            {
                using (var br = new BinaryReader(ms))
                {
                    br.BaseStream.Position = 16;
                    int headerBufferSize = br.ReadInt32();
                    offset = 20 + (headerBufferSize * 8) + 16 + 16;
                    br.BaseStream.Seek(offset, SeekOrigin.Begin);
                    var patchBytes = br.ReadBytes(NEW_PS3_MASK.Length);
                    patched = patchBytes.SequenceEqual(NEW_PS3_MASK) || patchBytes.SequenceEqual(LOCALH_MASK);                    
                }
            }           
            return patched;                
        }

        public bool MoggIsEncrypted(byte[] mData)
        {
            var numArray = new byte[] { 79, 103, 103, 83 };
            try
            {
                using (var ms = new MemoryStream(mData))
                {
                    using (var br = new BinaryReader(ms))
                    {
                        var cryptVersion = (CryptVersion)br.ReadInt32();
                        var num = br.ReadInt32();
                        br.BaseStream.Seek(num, SeekOrigin.Begin);
                        return !br.ReadBytes(4).SequenceEqual(numArray) || (cryptVersion != CryptVersion.x0A && cryptVersion != CryptVersion.xF0);
                    }
                }
            }
            catch (Exception)
            {
                return true;
            }
        }

        public bool DecY(string input, DecryptMode mode, string output = "")
        {
            var stream = new YargMoggReadStream(input);
            byte[] bytes = new byte[stream._fileStream.Length];
            stream.Read(bytes, 0, bytes.Length);
            stream._fileStream.Flush();
            stream._fileStream.Close();
            stream._fileStream.Dispose();

            if (mode == DecryptMode.ToFile && !string.IsNullOrEmpty(output))
            {
                DeleteFile(output);
                //write entire stream
                using (var fs = File.Create(output))
                {
                    using (var bw = new BinaryWriter(fs))
                    {
                        bw.Write(bytes);
                    }
                }
                //overwrite first byte so it can go straight into RB3 if needed
                //otherwise has 0XF0 which won't work in RB3
                using (var fs = File.OpenWrite(output))
                {
                    using (var bw = new BinaryWriter(fs))
                    {
                        bw.Write(0x0A);
                    }
                }
                return File.Exists(output);
            }
            else
            {
                RemoveMHeader(bytes, false, DecryptMode.ToMemory, output);
                return true;
            }
        }

        public bool DecM(byte[] mData, bool keep_header, bool isNext, DecryptMode mode, string mOut = "")
        {
            if (!MoggIsEncrypted(mData))
            {
                if (!keep_header) 
                {
                    return RemoveMHeader(mData, isNext, mode, mOut);
                }
                else if (mode == DecryptMode.ToFile)
                {
                    WriteOutData(mData, mOut);
                    return File.Exists(mOut);
                }
                return true;
            }
            mData = DeObfM(mData);
            CryptVersion version;
            using (var binaryReader = new BinaryReader(new MemoryStream(mData)))
            {
                version = (CryptVersion)binaryReader.ReadInt32();
            }
            if (!IsSupportedMoggType(version)) return false;            
            var moggFile = new MoggFile();
            var success = moggFile.Decrypt(mData, keep_header, false, mode, mOut);
            if (mode == DecryptMode.ToFile) return success && File.Exists(mOut);
            if (!success) return false;
            if (isNext)
            {
                NextSongOggData = moggFile.OggData;
            }
            else
            {
                PlayingSongOggData = moggFile.OggData;
            }
            return true;
        }

        public bool RemoveMHeader(byte[] mData, bool isNext, DecryptMode mode, string mOut)
        {
            byte[] buffer;
            using (var br = new BinaryReader(new MemoryStream(mData)))
            {
                br.ReadInt32();
                var num = br.ReadInt32();
                br.BaseStream.Seek(num, SeekOrigin.Begin);
                buffer = new byte[br.BaseStream.Length - num];
                br.Read(buffer, 0, buffer.Length);
            }
            if (mode == DecryptMode.ToMemory)
            {
                if (isNext)
                {
                    NextSongOggData = buffer;
                }
                else
                {
                    PlayingSongOggData = buffer;
                }
                return true;
            }
            WriteOutData(buffer, mOut);
            return File.Exists(mOut);
        }

        public void WriteOutData(byte[] mData, string mOut)
        {
            DeleteFile(mOut);
            using (var fs = File.Create(mOut))
            {
                using (var bw = new BinaryWriter(fs))
                {
                    bw.Write(mData);
                }
            }
        }

        public bool IsC3Mogg(byte[] mData)
        {
            var keys = new List<byte[]>
            {
                MoggCrypt.C3_PUBLIC_KEY_B,
                MoggCrypt.C3_PUBLIC_KEY_C,
                MoggCrypt.C3_PUBLIC_KEY_D,
                MoggCrypt.C3_PUBLIC_KEY_PS3
            };
            var isC3 = false;
            foreach (var key in keys)
            {
                using (var ms = new MemoryStream(mData))
                {
                    using (var br = new BinaryReader(ms))
                    {
                        var version = (CryptVersion)br.ReadInt32();
                        if (!IsSupportedMoggType(version)) return false;
                        var offset = br.ReadInt32();
                        br.BaseStream.Seek(offset - key.Length, SeekOrigin.Begin);
                        isC3 = br.ReadBytes(key.Length).SequenceEqual(key);
                        if (isC3) break;
                    }
                }
            }
            return isC3;
        }

        private static bool IsSupportedMoggType(CryptVersion version)
        {
            //0x0A is already decrypted, so we don't "support" it here
            //0xF0 is already decrypted YARG file, so we don't "support" it here
            return version == CryptVersion.x0B || version == CryptVersion.x0C ||
                version == CryptVersion.x0D || version == CryptVersion.x0E ||
                version == CryptVersion.x0F || version == CryptVersion.x10;
        }             

        public byte[] DeObfM(byte[] mData)
        {
            if (!MoggIsObfuscated(mData)) return mData;
            byte version;
            Int32 offset;
            using (var br = new BinaryReader(new MemoryStream(mData)))
            {
                version = br.ReadByte();
                br.ReadBytes(3);
                offset = br.ReadInt32();
            }
            byte[] key;
            switch ((ObfType)version)
            {
                case ObfType.x0B:
                    key = MoggCrypt.C3_PUBLIC_KEY_B;
                    version = (byte)CryptVersion.x0B;
                    break;
                case ObfType.x0C:
                    key = MoggCrypt.C3_PUBLIC_KEY_C;
                    version = (byte)CryptVersion.x0C;
                    break;
                case ObfType.x0D:
                    key = MoggCrypt.C3_PUBLIC_KEY_D;
                    version = (byte)CryptVersion.x0D;
                    break;
                case ObfType.x0E:
                    key = MoggCrypt.C3_PUBLIC_KEY_D;
                    version = (byte)CryptVersion.x0E;
                    break;
                case ObfType.x0F:
                    key = MoggCrypt.C3_PUBLIC_KEY_D;
                    version = (byte)CryptVersion.x0F;
                    break;
                case ObfType.x10:
                    key = MoggCrypt.C3_PUBLIC_KEY_D;
                    version = (byte)CryptVersion.x10;
                    break;
                case ObfType.xPS3:
                    key = MoggCrypt.C3_PUBLIC_KEY_PS3;
                    version = (byte)CryptVersion.x0D;
                    break;
                default:
                    return mData;
            }
            using (var ms = new MemoryStream(mData))
            {
                using (var bw = new BinaryWriter(ms))
                {
                    bw.Write(version);
                    bw.BaseStream.Seek(offset - key.Length, SeekOrigin.Begin);
                    bw.Write(key);
                }
            }
            return mData;
        }

        public byte[] ObfM(byte[] mData)
        {
            if (MoggIsObfuscated(mData) || !IsC3Mogg(mData))
            {
                return mData;
            }
            byte version;
            Int32 offset;
            using (var br = new BinaryReader(new MemoryStream(mData)))
            {
                version = br.ReadByte();
                br.ReadBytes(3);
                offset = br.ReadInt32();
            }
            byte[] key;
            switch ((CryptVersion)version)
            {
                case CryptVersion.x0B:
                    key = OBF_KEY_SHORT;
                    version = (byte)ObfType.x0B;
                    break;
                case CryptVersion.x0C:
                    key = OBF_KEY_LONG;
                    version = (byte)ObfType.x0C;
                    break;
                case CryptVersion.x0D:
                    key = OBF_KEY_LONG;
                    version = isPS3Mogg(mData) ? (byte)ObfType.xPS3 : (byte)ObfType.x0D;
                    break;
                case CryptVersion.x0E:
                    key = OBF_KEY_LONG;
                    version = (byte)ObfType.x0E;
                    break;
                case CryptVersion.x0F:
                    key = OBF_KEY_LONG;
                    version = (byte)ObfType.x0F;
                    break;
                case CryptVersion.x10:
                    key = OBF_KEY_LONG;
                    version = (byte)ObfType.x10;
                    break;
                default:
                    return mData;
            }
            using (var ms = new MemoryStream(mData))
            {
                using (var bw = new BinaryWriter(ms))
                {
                    bw.Write(version);
                    bw.BaseStream.Seek(offset - key.Length, SeekOrigin.Begin);
                    bw.Write(key);
                }
            }
            return mData;
        }

        private bool isPS3Mogg(byte[] mData)
        {
            var isPS3 = false;
            var key = MoggCrypt.C3_PUBLIC_KEY_PS3;
            using (var ms = new MemoryStream(mData))
            {
                using (var br = new BinaryReader(ms))
                {
                    var version = (CryptVersion)br.ReadInt32();
                    if (!IsSupportedMoggType(version)) return false;
                    var offset = br.ReadInt32();
                    br.BaseStream.Seek(offset - key.Length, SeekOrigin.Begin);
                    isPS3 = br.ReadBytes(key.Length).SequenceEqual(key);
                }
            }
            return isPS3;
        }

        public bool MoggIsObfuscated(byte[] mData)
        {
            try
            {
                using (var br = new BinaryReader(new MemoryStream(mData)))
                {
                    var version = (ObfType)br.ReadByte();
                    return version == ObfType.x0B || version == ObfType.x0C ||
                        version == ObfType.x0D || version == ObfType.x0E ||
                        version == ObfType.x0F || version == ObfType.x10 || version == ObfType.xPS3; 
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
                
        private readonly byte[] OBF_KEY_SHORT =
        {
            0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3
        };
        private readonly byte[] OBF_KEY_LONG =
        {
            0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
            0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
            0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
            0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
            0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3
        };
        private enum ObfType
        {
            x0B = 0xC3,
            x0C = 0xCC,
            x0D = 0xCD,
            x0E = 0xCE,
            x0F = 0xCF,
            x10 = 0xC1,
            xPS3 = 0x33
        }
        #endregion
    }
}
