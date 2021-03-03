using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

namespace CT_Font_Helper
{

    class Program
    {
		static void Decrypt(string src, string dst, string key)
        {

			FileStream file = File.Open(src, FileMode.Open);
			BinaryReader reader = new BinaryReader(file);

			int size = (int)(file.Length / 4);
			int sizeNoHeader = size - 2;

			//List<uint> keyData = new List<uint>(1042);
			List<uint> dataNoHeader = new List<uint>(sizeNoHeader);

			//ulong header = BitConverter.ToUInt64(BitConverter.GetBytes(reader.ReadUInt64()).Reverse().ToArray(), 0);
			ulong header = BitConverter.ToUInt64(reader.ReadBytes(8).Reverse().ToArray(), 0);
			while (dataNoHeader.Count != sizeNoHeader)
			{
				uint tmp = (uint)(reader.ReadByte() << 24 | reader.ReadByte() << 16 | reader.ReadByte() << 8 | reader.ReadByte());
				dataNoHeader.Add(tmp);// reader.ReadInt32());
			}
			reader.Close();

			Decryptor d = new Decryptor(key);

			var watch = new System.Diagnostics.Stopwatch();
			Console.WriteLine($"Decrypting. This may take a while.");
			watch.Start();
			uint[] tmpArray = d.Decrypt(header, dataNoHeader);
			watch.Stop();

			Console.WriteLine($"Decrypted. Time Elapsed: {watch.Elapsed}");

			using (var fileOut = File.OpenWrite(dst))
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

		static void Encrypt(string src, string dst, string key)
        {
			FileStream file = File.OpenRead(src);
			BinaryReader br = new BinaryReader(file);

			int size = (int)(file.Length / 4);
			int sizeNoHeader = size - 2;

			//List<uint> keyData = new List<uint>(1042);
			List<uint> dataNoHeader = new List<uint>(sizeNoHeader);

			
			ulong header = BitConverter.ToUInt64(br.ReadBytes(8).Reverse().ToArray(), 0);

			while (dataNoHeader.Count != sizeNoHeader)
			{
				uint tmp = (uint)(br.ReadByte() << 24 | br.ReadByte() << 16 | br.ReadByte() << 8 | br.ReadByte());
				dataNoHeader.Add(tmp);
			}
			br.Close();

			Decryptor d = new Decryptor(key);
			var watch = new System.Diagnostics.Stopwatch();
			Console.WriteLine($"Encrypting. This may take a while.");
			watch.Start();
			uint[] tmpArray = d.Encrypt(header, dataNoHeader);
			watch.Stop();

			Console.WriteLine($"Encrypted. Time Elapsed: {watch.Elapsed}");
			Console.WriteLine($"Writing file.");

			using (var fileOut = File.OpenWrite(dst))
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

		static void Main(string[] args)
        {
			string srcPath;
			string keyPath;
			string destPath;
			ConsoleKeyInfo action;

#if DEBUG
			srcPath = @"testIn.bin";
			keyPath = @"key.bin";
			destPath = "testOut.bin";
			action = "E";
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
