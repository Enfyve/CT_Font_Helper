using System;
using System.Collections.Generic;
using System.IO;

namespace CT_Font_Helper
{
    public class Cryptor
    {
        private const ulong headerX = 0x75FA2995054D415F;
        private const uint headerH = 0x6010C7FD;
        private const uint headerL = 0x8339EBB7;

        public List<uint> keyData = null;

        public Cryptor(string keyFilePath)
        {
            using (var keyFile = File.Open(keyFilePath, FileMode.Open))
            {
                int keySize = (int)(keyFile.Length / 4);
                keyData = new List<uint>(keySize);

                BinaryReader br = new BinaryReader(keyFile);
                
                // Read to eof
                while (keyData.Count != keySize)
                {
                    keyData.Add(br.ReadUInt32());
                }
            }
        }

        public uint[] Decrypt(ulong header, List<uint> fileData)
        {
            header ^= headerX;                                              // XOR header with 75FA2995 054D415F

            int decrpytedSize = fileData.Count;
            uint[] decrypted = new uint[decrpytedSize];
            uint hi_int = 0;
            uint lo_int = 0;
            for (int i = 0; i < decrpytedSize; i += 2)
            {
                hi_int = fileData[i];
                lo_int = fileData[i + 1];
                uint tmp = 0;

                for (int j = 16; j > 0; j--)
                {
                    tmp = hi_int ^ keyData[j + 1];                          // set tmp to hi_int of last iteration XORd with key[j+1]

                    hi_int = keyData[(int)(tmp >> 0x18) + 0x12];            // keyData at index:       first byte of tmp + 18
                    hi_int += keyData[(int)(tmp >> 0x10 & 0xff) + 0x112];   // plus keyData at index: second byte of tmp + 274 (256+18)
                    hi_int ^= keyData[(int)(tmp >> 8 & 0xff) + 0x212];      // XOR  keyData at index:  third byte of tmp + 530 (512+18)
                    hi_int += keyData[(int)(tmp & 0xff) + 0x312];           // plus keyData at index: fourth byte of tmp + 786 (768+18)
                    hi_int ^= lo_int;                                       // XOR lo_int from last iteration
                    lo_int = tmp;                                           // lo_int becomes tmp after calculations finished
                }

                decrypted[i] = lo_int ^ keyData[0] ^ (uint)(header >> 32); 
                decrypted[i + 1] = hi_int ^ keyData[1] ^ (uint)(header); 
                header = ((ulong)fileData[i] << 32 | fileData[i + 1]); // header becomes next 2 ints in fileData
            }
            return decrypted;
        }


        public uint[] Encrypt(List<uint> fileData)
        {
            ulong header = headerX;

            for (int j = 0; j < fileData.Count-1; j+= 2)
            {
                uint chunkH = fileData[j] ^ (uint)(header >> 32);
                uint chunkL = fileData[j + 1] ^ (uint)(header & 0xFFFFFFFF);

                uint tmp1 = 0;
                uint tmp2 = chunkH;
                uint tmp3 = chunkL;
                for (int i = 0; i < 16; i++)
                {
                    tmp1 = tmp2 ^ keyData[i];
                    tmp2 = (keyData[(int)(tmp1 >> 0x18) + 0x12] +
                            keyData[(int)(tmp1 >> 0x10 & 0xff) + 0x112] ^
                            keyData[(int)(tmp1 >> 8 & 0xff) + 0x212]) +
                            keyData[(int)(tmp1 & 0xff) + 0x312] ^ tmp3;
                    tmp3 = tmp1;
                }

                chunkH = keyData[0x11] ^ tmp1;
                chunkL = keyData[0x10] ^ tmp2;

                header = (ulong)chunkH << 32 | chunkL;

                fileData[j] = chunkH;
                fileData[j+1] = chunkL;
            }
        
            return fileData.ToArray();
        }

    }
}

