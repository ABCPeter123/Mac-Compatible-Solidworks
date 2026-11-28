// Independent CAD prerequisite controls. No SOLIDWORKS media or credentials.
// Compile twice with /platform:x86 and /platform:x64 using Microsoft CSC.
using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Forms;
using Microsoft.Win32;

class CadPrerequisites
{
    static bool Core()
    {
        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"))
            return k != null && Convert.ToInt32(k.GetValue("Release", 0)) >= 533320
                && Environment.Version.Major == 4 && System.Threading.Tasks.Task.Factory.StartNew(() => 42).Result == 42;
    }

    static bool WinForms()
    {
        using (var button = new Button())
        using (var image = new Bitmap(128, 48))
        {
            button.Size = new Size(128, 48);
            button.Text = "SWCOMPAT";
            button.CreateControl();
            button.DrawToBitmap(image, new Rectangle(0, 0, 128, 48));
            int first = image.GetPixel(0, 0).ToArgb();
            for (int y = 0; y < 48; y++)
                for (int x = 0; x < 128; x++)
                    if (image.GetPixel(x, y).ToArgb() != first) return true;
            return false;
        }
    }

    static void WpfStage(string stage)
    {
        Console.Error.WriteLine("SWCOMPAT_WPF_STAGE=" + stage);
        Console.Error.Flush();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static bool Wpf()
    {
        WpfStage("ENTER");
        var visual = new DrawingVisual();
        WpfStage("VISUAL");
        using (DrawingContext dc = visual.RenderOpen())
        {
            dc.DrawRectangle(System.Windows.Media.Brushes.Red, null, new System.Windows.Rect(0, 0, 32, 32));
            dc.DrawRectangle(System.Windows.Media.Brushes.Blue, null, new System.Windows.Rect(32, 0, 32, 32));
        }
        WpfStage("DRAWN");
        var bitmap = new RenderTargetBitmap(64, 32, 96, 96, PixelFormats.Pbgra32);
        WpfStage("BITMAP");
        bitmap.Render(visual);
        WpfStage("RENDERED");
        byte[] pixels = new byte[64 * 32 * 4];
        bitmap.CopyPixels(pixels, 64 * 4, 0);
        WpfStage("COPIED");
        int a = (16 * 64 + 16) * 4, b = (16 * 64 + 48) * 4;
        return pixels[a+2] > 240 && pixels[a] < 16 && pixels[b] > 240 && pixels[b+2] < 16;
    }

    static bool Wcf()
    {
        var binding = new BasicHttpBinding();
        if (binding.CreateBindingElements().Count < 2) return false;
        var serializer = new DataContractSerializer(typeof(string));
        using (var stream = new MemoryStream())
        {
            serializer.WriteObject(stream, "SWCOMPAT");
            stream.Position = 0;
            return (string)serializer.ReadObject(stream) == "SWCOMPAT";
        }
    }

    static bool Com()
    {
        Type t = Type.GetTypeFromProgID("Scripting.Dictionary", false);
        if (t == null) return false;
        object o = Activator.CreateInstance(t);
        try
        {
            t.InvokeMember("Add", BindingFlags.InvokeMethod, null, o, new object[] {"probe", 42});
            return Convert.ToBoolean(t.InvokeMember("Exists", BindingFlags.InvokeMethod, null, o, new object[] {"probe"}));
        }
        finally { if (Marshal.IsComObject(o)) Marshal.FinalReleaseComObject(o); }
    }

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length != 1 && args.Length != 2) return 2;
        string mode = args[0];
        if (mode != "core" && mode != "winforms" && mode != "wpf" && mode != "wcf" && mode != "com") return 2;
        bool native = Type.GetType("Mono.Runtime") == null && Environment.Version.Major == 4;
        bool pass = false;
        string error = "00000000";
        try
        {
            if (native)
                switch (mode)
                {
                    case "core": pass = Core(); break;
                    case "winforms": pass = WinForms(); break;
                    case "wpf": WpfStage("DISPATCH"); pass = Wpf(); break;
                    case "wcf": pass = Wcf(); break;
                    case "com": pass = Com(); break;
                }
        }
        catch (Exception ex) {
            error = unchecked((uint)Marshal.GetHRForException(ex)).ToString("X8");
            if (mode == "wpf")
            {
                WpfStage("MANAGED_EXCEPTION");
                Exception inner = ex.InnerException;
                if (inner != null)
                    Console.Error.WriteLine("SWCOMPAT_WPF_INNER_HRESULT=" + unchecked((uint)Marshal.GetHRForException(inner)).ToString("X8"));
            }
        }
        string packet = "SWCOMPAT_CAD_SCHEMA=1\n"
            + "SWCOMPAT_CAD_MODE=" + mode + "\n"
            + "SWCOMPAT_CAD_BITS=" + (IntPtr.Size * 8) + "\n"
            + "SWCOMPAT_CAD_NATIVE=" + (native ? "YES" : "NO") + "\n"
            + "SWCOMPAT_CAD_RESULT=" + (pass ? "PASS" : "FAIL") + "\n"
            + "SWCOMPAT_CAD_HRESULT=" + error + "\n";
        if (args.Length == 2)
        {
            using (var file = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write))
            using (var writer = new StreamWriter(file, new System.Text.UTF8Encoding(false)))
                writer.Write(packet);
        }
        else Console.Write(packet);
        return pass ? 0 : 1;
    }
}
