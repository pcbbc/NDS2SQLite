using ICSharpCode.SharpZipLib.Zip.Compression.Streams;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NDS2SQLite
{
	/*
	AQ-- = rdQs8QKJaULIUwYd7poRFA--
	Ag-- = GYOsN9e7CPyQSlXuPWdeTQ--
	Aw-- = mDRS8QnJtkdEskluRVrKiQ--
	BA-- = Qbp4utvivA3mLyIeJFSriQ--
	BQ-- = 0wZ4nhK08NzjQgLQd9wzvg--
	Bg-- = qrN/FSyetIySirwlYupFrg--
	Bw-- = pxMJ+vc90BcIpg5npPzWBQ--
	CA-- = YKt9H8zoYGntPTZJTaL/DQ--
	CQ-- = Qw4wOGuqWh0LVHP/qxf2kA--
	Cg-- = E9akTnuZvMPPZyJK4V+kmA--
	Cw-- = 7cUt7Q6768jtP3WU+7yqZA--

	<configitem EBSDKConfigFile="./cfg/NAV/EBA/EBAConfigs.xml"/>
	<configitem MapFolderPath="/sdc1/maps/01/nds"/>
	<configitem DefaultPositionX="1200626" DefaultPositionY="6871234"/>
	<configitem MapKey="My16BytePassword"/>
	<configitem MapKey="z463rTyK9YS3JIPq"/>
	<configitem MapKey="owTOajO2tcftkGWg"/>
	<configitem MapKey="3TzgjvOpJYS1VNfa"/>
	<configitem MapKey="8vJRhpfuytHTxWH2"/>
	<configitem MapKey="5b2j5bLzM1lIdkiI"/>
	<configitem MapKey="Lr2YMWxM3RRkB9GI"/>
	<configitem MapKey="ELytUVOx2e6CIBCb"/>
	<configitem MapKey="vLCgUQpEKnS8wx1J"/>
	<configitem MapKey="HxFOBYqrya0QaDQN"/>
	<configitem MapKey="5qiXreuKrL8g2iJK"/>
	*/

	internal class Program
	{
		static Stream reader;
		static Stream writer;
		static byte[] header = new byte[200];
		static AesManaged aes = new AesManaged();
		static byte[] iv = new byte[16];
		static ICryptoTransform encryptor;

		private static string[] keys = new string[]
		{
			"",
			"My16BytePassword",
			"z463rTyK9YS3JIPq",
			"owTOajO2tcftkGWg",
			"3TzgjvOpJYS1VNfa",
			"8vJRhpfuytHTxWH2",
			"5b2j5bLzM1lIdkiI",
			"Lr2YMWxM3RRkB9GI",
			"ELytUVOx2e6CIBCb",
			"vLCgUQpEKnS8wx1J",
			"HxFOBYqrya0QaDQN",
			"5qiXreuKrL8g2iJK",
		};

		static void Main(string[] args)
		{
			aes.Mode = CipherMode.ECB;
			aes.Padding = PaddingMode.None;
			aes.KeySize = 128;

			if (args.Length != 1 || (!File.Exists(args[0]) && !Directory.Exists(args[0])))
			{
				string procname = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
				Console.WriteLine("Syntax:");
				Console.WriteLine($"{procname} <filename>       Uncompresses single NDS database");
				Console.WriteLine($"{procname} <path>           Recursively uncompresses all NDS databases under path");
				return;
			}
			if (File.Exists(args[0]))
			{
				Program.ExpandFile(args[0]);
			}
			else
			{
				foreach (string filename in Directory.GetFiles(args[0], "*.nds", SearchOption.AllDirectories))
				{
					Program.ExpandFile(filename);
				}
			}
		}

		static void ExpandFile(string filename)
		{
			Console.WriteLine($"{filename} ...");
			string filein = filename;
			string fileout = Path.ChangeExtension(filein, ".sqlite");

			using (Program.reader = File.OpenRead(filein))
			using (Program.writer = File.Create(fileout))
			{
				Program.reader.Read(Program.header, 0, Program.header.Length);
				ulong dbsize = Program.GetUInt64(Program.header, 140);
				uint pgsize = Program.GetUInt32(Program.header, 172);
				int pages = (int)(dbsize / pgsize);

				for (int p = 0; p < pages; p++)
				{
					byte[] mapentry = new byte[8];
					Program.reader.Position = 200 + p * 8;
					Program.reader.Read(mapentry, 0, mapentry.Length);
					ulong mapval = Program.GetUInt64(mapentry, 0);
					long offset = (long)(mapval >> 24);
					int size = (int)((mapval >> 7) & 0x1FFFF);
					int unused = (int)(mapval & 0x7F);

					byte[] buffer = new byte[pgsize];
					if (offset == 0)
					{
						//Empty block
						Program.writer.Write(buffer, 0, buffer.Length);
						continue;
					}

					Program.reader.Position = offset;
					byte[] pageentry = new byte[6];
					Program.reader.Read(pageentry, 0, pageentry.Length);
					uint pageno = Program.GetUInt32(pageentry, 0) >> 1;
					uint pagelen = Program.GetUInt32(pageentry, 2) & 0x1FFFF;

					if (pageno != p + 1 || pagelen < size)
					{
						//Invalid page entry
						Console.WriteLine($"Invalid page {p}");
						Program.writer.Write(buffer, 0, buffer.Length);
						continue;
					}

					byte[] page = new byte[size];
					Program.reader.Read(page, 0, page.Length);
					if (p == 0)
					{
						bool valid = false;
						foreach (string key in Program.keys)
						{
							byte[] copypage = (byte[])page.Clone();
							if (string.IsNullOrEmpty(key))
							{
								Program.encryptor = null;
							}
							else
							{
								byte[] iv = new byte[16];
								Program.encryptor = aes.CreateDecryptor(Encoding.ASCII.GetBytes(key), iv);
							}
							if (Program.ExpandPage(copypage, buffer))
							{
								string sig = Encoding.ASCII.GetString(buffer, 0, 6);
								if (sig == "SQLite")
								{
									valid = true;
									break;
								}
							}
						}
						if (!valid)
						{
							Console.WriteLine("Invalid SQLLite database");
							return;
						}
					}

					if (!Program.ExpandPage(page, buffer))
					{
						Console.WriteLine($"Uncompress error page {p}");

					}
					Program.writer.Write(buffer, 0, buffer.Length);
				}
			}
		}

		static bool ExpandPage(byte[] data, byte[] buffer)
		{
			try
			{
				if (Program.encryptor != null)
				{
					using (MemoryStream ms = new MemoryStream())
					{
						using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write, true))
						{
							int blks = Math.Min(4, data.Length / 0x10);
							cs.Write(data, 0, blks * 0x10);
						}
						byte[] decrypted = ms.ToArray();
						Array.Copy(decrypted, 0, data, 0, decrypted.Length);
					}
				}
				using (InflaterInputStream inflater = new InflaterInputStream(new MemoryStream(data)))
				{
					int read = inflater.Read(buffer, 0, buffer.Length);
					return read == buffer.Length;
				}
			}
			catch
			{
				return false;
			}
		}

		static ushort GetUInt16(byte[] buffer, int offset)
		{
			return (ushort)(
				(buffer[offset + 0] << 8) |
				(buffer[offset + 1] << 0));
		}

		static uint GetUInt32(byte[] buffer, int offset)
		{
			return (uint)(
				(buffer[offset + 0] << 24) |
				(buffer[offset + 1] << 16) |
				(buffer[offset + 2] << 8) |
				(buffer[offset + 3] << 0));
		}

		static ulong GetUInt64(byte[] buffer, int offset)
		{
			return (ulong)(
				((long)buffer[offset + 0] << 56) |
				((long)buffer[offset + 1] << 48) |
				((long)buffer[offset + 2] << 40) |
				((long)buffer[offset + 3] << 32) |
				((long)buffer[offset + 4] << 24) |
				((long)buffer[offset + 5] << 16) |
				((long)buffer[offset + 6] << 8) |
				((long)buffer[offset + 7] << 0));
		}
	}
}
