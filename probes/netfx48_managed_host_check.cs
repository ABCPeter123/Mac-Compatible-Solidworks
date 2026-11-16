// Self-authored managed fixture; only a real managed invocation returns 42.
// No vendor code, external payloads, registry spoofing, or environment dumps.
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

public static class SWCompatClr48
{
    public static int Run(string input)
    {
        try
        {
            if (input != "probe" || Type.GetType("Mono.Runtime", false) != null)
                return 41;
            if (Environment.Version.Major != 4)
                return 41;
            int value = Task.Factory.StartNew(() => 7 * 6).Result;
            var doc = new XmlDocument();
            doc.LoadXml("<cad><part>42</part></cad>");
            using (var sha = SHA256.Create())
            {
                var digest = sha.ComputeHash(Encoding.UTF8.GetBytes("probe"));
                return value == 42 && doc.DocumentElement.SelectSingleNode("part").InnerText == "42"
                    && digest.Length == 32 ? 42 : 41;
            }
        }
        catch { return 41; }
    }
}