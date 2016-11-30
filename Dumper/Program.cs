//
//  File Name: Program.cs
//  Project Name: Dumper
//
//  Created by Alexandro Luongo on 30/11/2016.
//  Copyright © 2016 Alexandro Luongo. All rights reserved.
//

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PwnFast
{
    /// <summary>
    /// Dumper: Utility to extract API keys from signed PokeFast APKs.
    /// </summary>
    internal class Dumper
    {
        /// <summary>
        /// DIRECTORY: Name of the directory to look the APKs for.
        /// </summary>
        private static readonly string DIRECTORY = "Files";

        /// <summary>
        /// DESTINATION: Name of the file which will contain the extracted API keys.
        /// </summary>
        private static readonly string DESTINATION = "Keys.txt";

        /// <summary>
        /// Keys: A list of API keys.
        /// </summary>
        private static List<string> Keys;

        /// <summary>
        /// Print informations, initialize global variables.
        /// </summary>
        private static void Init()
        {
            Console.WriteLine("PwnFast - PokeFast Cracking Utility");
            Console.WriteLine("Copyright (C) 2016 - W00dL3cs (Alexandro Luongo)");
            Console.WriteLine();

            Keys = new List<string>();

            Directory.CreateDirectory(DIRECTORY);
        }

        /// <summary>
        /// Entry point of the application.
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            Init();

            DumpKeys();

            StayOpen();
        }

        /// <summary>
        /// Empty loop to keep the application alive.
        /// </summary>
        private static void StayOpen()
        {
            while (true) ;
        }

        /// <summary>
        /// Scan for PokeFast APKs and perform dumping operations.
        /// </summary>
        private static async void DumpKeys()
        {
            Console.WriteLine(string.Format("Loading APKs inside \"{0}\" folder...", DIRECTORY));

            var APKs = Directory.GetFiles(DIRECTORY, "*.apk", SearchOption.TopDirectoryOnly);

            Console.WriteLine(string.Format("Successfully found {0} APKs!", APKs.Length));
            Console.WriteLine();

            var Tasks = new List<Task>();

            foreach (var APK in APKs)
            {
                Tasks.Add(DumpKey(APK));
            }

            await Task.WhenAll(Tasks);

            File.WriteAllLines(DESTINATION, Keys.ToArray());

            Console.WriteLine();
            Console.WriteLine(string.Format("A total of {0} keys has been written to the file \"{1}\".", Keys.Count, DESTINATION));
            Console.WriteLine();

            Console.WriteLine("Press a key to terminate.");
            Console.ReadKey();

            Environment.Exit(0);
        }

        /// <summary>
        /// Scan a PokeFast APK and dump its dynamic API key.
        /// </summary>
        /// <param name="APK">Name of the APK to scan.</param>
        /// <returns></returns>
        private static async Task DumpKey(string APK)
        {
            try
            {
                Console.WriteLine("Reading {0}...", APK);

                using (var Archive = ZipFile.OpenRead(APK))
                {
                    var Resources = Archive.GetEntry("resources.arsc");

                    if (Resources != null)
                    {
                        using (var Reader = new StreamReader(Resources.Open()))
                        {
                            var Content = await Reader.ReadToEndAsync();

                            var Regex = new Regex("([0-9A-Za-z]{8}[-][0-9A-Za-z]{4}[-][0-9A-Za-z]{4}[-][0-9A-Za-z]{4}[-][0-9A-Za-z]{12})", RegexOptions.Multiline);

                            foreach (Match Match in Regex.Matches(Content))
                            {
                                var Key = Match.Groups[1].Value;

                                Console.WriteLine(string.Format("API key found: {0}!", Key));

                                Keys.Add(Key);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(string.Format("Fatal exception while reading APK: {0}!", APK));
                Console.WriteLine(string.Format("Error message: {0}", e.Message));
            }
        }
    }
}
