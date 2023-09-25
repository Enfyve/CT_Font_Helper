using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

namespace CT_Font_Helper
{

    class Program
    {
		static void Decrypt(string inFile, string outFile, string key)
        {

			FileStream file = File.Open(inFile, FileMode.Open);
			BinaryReader reader = new BinaryReader(file);

			int size = (int)(file.Length / 4);

			List<uint> data = new List<uint>(size-2);

			ulong header = reader.ReadUInt64();

            while (data.Count != size-2)
			{
                uint tmp = (uint)(reader.ReadByte() << 24 | reader.ReadByte() << 16 | reader.ReadByte() << 8 | reader.ReadByte());
                data.Add(tmp);
            }
			reader.Close();

			Cryptor cryptor = new Cryptor(key);

			var watch = new System.Diagnostics.Stopwatch();
			Console.WriteLine($"Decrypting. This may take a while.");

			watch.Start();
			uint[] tmpArray = cryptor.Decrypt(header, data);
			watch.Stop();

			Console.WriteLine($"Decrypted. Time Elapsed: {watch.Elapsed}");

			using (var fileOut = File.OpenWrite(outFile))
			{
				var writer = new BinaryWriter(fileOut);
				foreach (uint i in tmpArray)
				{
					// Swap endian before writing
					writer.Write(BitConverter.ToUInt32(BitConverter.GetBytes(i).Reverse().ToArray(), 0));
				}
			}

			Console.WriteLine("Success. Press any key to exit.");
			Console.ReadKey();
		}

		static void Encrypt(string inFile, string outFile, string key)
        {
			FileStream file = File.OpenRead(inFile);
			BinaryReader br = new BinaryReader(file);

			int size = (int)(file.Length / 4);
			int sizeRemainder = (int)(file.Length % 8);

			List<uint> data = new List<uint>(size);

			while (data.Count != size)
			{
				uint tmp = (uint)(br.ReadByte() << 24 | br.ReadByte() << 16 | br.ReadByte() << 8 | br.ReadByte());
				data.Add(tmp);
			}

			if (sizeRemainder != 0)
			{
				List<byte> remainingBytes = new List<byte>(8);

				remainingBytes = br.ReadBytes((int)(file.Length - br.BaseStream.Position)).Reverse().ToList();

				for (int i = 0; remainingBytes.Count < 8; i++)
				{
					remainingBytes.Add(0);
				}
						
				data.Add(BitConverter.ToUInt32(remainingBytes.ToArray(), 0));

				if (sizeRemainder > 4)
					data.Add(BitConverter.ToUInt32(remainingBytes.ToArray(), 4));
            }

			br.Close();

			Cryptor d = new Cryptor(key);
			var watch = new System.Diagnostics.Stopwatch();
			Console.WriteLine($"Encrypting. This may take a while.");
			watch.Start();
			uint[] tmpArray = d.Encrypt(data);
			watch.Stop();

			Console.WriteLine($"Encrypted. Time Elapsed: {watch.Elapsed}");
			Console.WriteLine($"Writing file.");

			using (var fileOut = File.OpenWrite(outFile))
			{
				var writer = new BinaryWriter(fileOut);

				// Write header used for decryption (0x00000000, 0x00000000)
				writer.Write(0); 
				writer.Write(0);

                foreach (uint i in tmpArray)
				{
					// Swap endian before writing
					writer.Write(BitConverter.ToUInt32(BitConverter.GetBytes(i).Reverse().ToArray(), 0));
				}
			}

			Console.WriteLine("Success. Press any key to exit.");
			Console.ReadKey();
		}

		static void Main(string[] args)
        {
			string srcPath;
			string keyPath;
			string destPath;
			ConsoleKeyInfo action;
#if DEBUG
			srcPath = @"in.bin";
			keyPath = @"key.bin";
			destPath = "out.bin";
			action = new ConsoleKeyInfo('E', ConsoleKey.E, false, false, false);			
#else
			Console.Write("Specify input file: ");
			srcPath = Console.ReadLine();
			Console.Write("Specify key file: ");
			keyPath = Console.ReadLine();
			Console.Write("Enter output file name: ");
			destPath = Console.ReadLine();

			Console.Write("Decrypt or Encrypt? [D|E] (default decrypt): ");
			action = Console.ReadKey();
			Console.WriteLine();
#endif

			switch (action.Key)
            {
				case ConsoleKey.Enter:
				case ConsoleKey.D:   // Decrypt
					Decrypt(srcPath, destPath, keyPath);
					break;
				case ConsoleKey.E:   // Encrypt
					Encrypt(srcPath, destPath, keyPath);
					break;
				default:
					Console.WriteLine("Unknown action. Press any key to exit.");
					Console.ReadKey();
					break;
			}

			return;
		}
    }
}
