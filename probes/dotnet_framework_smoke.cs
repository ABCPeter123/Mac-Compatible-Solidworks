// Independent .NET Framework 4.x executable, compiled on Windows CI.
// It exercises managed tasks, file IO, XML and hashing, not merely mscoree.dll.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

public static class SWCompatManagedSmoke {
    public static int Main() {
        string path = null;
        try {
            int result = Task.Run(() => 7 * 6).GetAwaiter().GetResult();
            if (result != 42) throw new Exception("Task result mismatch");
            XmlDocument xml = new XmlDocument();
            xml.LoadXml("<model><part id='42'/></model>");
            if (xml.SelectSingleNode("/model/part").Attributes["id"].Value != "42")
                throw new Exception("XML parse mismatch");
            byte[] text = Encoding.UTF8.GetBytes("swcompat-managed-probe");
            byte[] hash;
            using (SHA256 algorithm = SHA256.Create()) {
                hash = algorithm.ComputeHash(text);
            }
            if (hash.Length != 32) throw new Exception("SHA256 mismatch");
            path = Path.Combine(Path.GetTempPath(),
                "swcompat-managed-" + Guid.NewGuid().ToString("N") + ".tmp");
            File.WriteAllBytes(path, hash);
            if (File.ReadAllBytes(path).Length != hash.Length)
                throw new Exception("Managed IO mismatch");
            Console.WriteLine("SWCOMPAT_DOTNET_CLR_MAJOR=" + Environment.Version.Major);
            Console.WriteLine("SWCOMPAT_DOTNET_TASKS=PASS");
            Console.WriteLine("SWCOMPAT_DOTNET_XML=PASS");
            Console.WriteLine("SWCOMPAT_DOTNET_CRYPTO=PASS");
            Console.WriteLine("SWCOMPAT_DOTNET_FILEIO=PASS");
            Console.WriteLine("SWCOMPAT_DOTNET=PASS");
            return 0;
        } catch (Exception ex) {
            Console.WriteLine("SWCOMPAT_DOTNET_FAILURE_TYPE=" + ex.GetType().Name);
            Console.WriteLine("SWCOMPAT_DOTNET=FAIL");
            return 1;
        } finally {
            if (path != null) {
                try { File.Delete(path); } catch { }
            }
        }
    }
}
