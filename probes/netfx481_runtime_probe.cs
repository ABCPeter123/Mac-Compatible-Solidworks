// Original nonproprietary .NET Framework runtime verification fixture.
// A managed-code success under Wine Mono is NOT Microsoft Framework 4.8.1.
// Compiled from source on Windows Server using Framework64 csc.exe.
using System;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

class SWCompatNetFx481
{
    static void Main()
    {
        Console.WriteLine("SWCOMPAT_NETFX481_SCHEMA=1");
        try
        {
            object release = Registry.GetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full",
                "Release", null);
            int releaseNumber = release is int ? (int)release : 0;
            Console.WriteLine("SWCOMPAT_NETFX481_REGISTRY=" +
                (releaseNumber >= 533320 ? "AT_LEAST_481" :
                releaseNumber > 0 ? "BELOW_481" : "NOT_FOUND"));
        }
        catch
        {
            Console.WriteLine("SWCOMPAT_NETFX481_REGISTRY=UNAVAILABLE");
        }

        try
        {
            Type mono = Type.GetType("Mono.Runtime", false);
            string family = mono != null ? "MONO" :
                (Environment.Version.Major == 4 ? "MICROSOFT_CLR_CANDIDATE" : "UNKNOWN");
            Console.WriteLine("SWCOMPAT_NETFX481_CLR_FAMILY=" + family);
        }
        catch
        {
            Console.WriteLine("SWCOMPAT_NETFX481_CLR_FAMILY=UNKNOWN");
        }

        bool passed = false;
        try
        {
            int task = Task.Factory.StartNew(() => 42).Result;
            XmlDocument xml = new XmlDocument();
            xml.LoadXml("<a><b>ready</b></a>");
            string value = xml.DocumentElement.SelectSingleNode("b").InnerText;
            using (SHA256 hash = SHA256.Create())
            {
                byte[] digest = hash.ComputeHash(Encoding.UTF8.GetBytes(value));
                passed = task == 42 && value == "ready" && digest.Length == 32;
            }
        }
        catch
        {
            passed = false;
        }
        Console.WriteLine("SWCOMPAT_NETFX481_MANAGED=" + (passed ? "PASS" : "FAIL"));
        Environment.ExitCode = passed ? 0 : 1;
    }
}
