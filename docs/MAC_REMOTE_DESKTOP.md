# Use genuine SOLIDWORKS on a Mac without a Windows VM on the Mac

This is a usable, separate fallback from our experimental native Wine interoperability work. SOLIDWORKS runs on a **licensed Windows 11 x86-64 Pro/Enterprise workstation**, while your Mac uses Microsoft's free Windows App to interact with the Windows desktop. CAD geometry, licensing and graphics run on the Windows machine, not on Wine or a Mac VM.

This does **not** make the Windows SOLIDWORKS executable native to macOS, does not work offline, and requires an available Windows machine or a Windows x86-64 GPU workstation rented from a provider. You must hold the appropriate SOLIDWORKS entitlement. Remote graphics performance varies by host GPU, network and RDP implementation.

## On the Windows host

1. Ensure Windows 11 is a supported Pro/Enterprise x86-64 edition, and install/activate the genuine SOLIDWORKS product normally on the Windows workstation. Install an appropriate graphics driver and test a sketch, extrusion, rotate and save locally first.
2. In Windows Settings > System > Remote Desktop, enable Remote Desktop, keep Network Level Authentication on, and grant access only to the intended Windows account.
3. Use a **private LAN** or secure VPN such as Tailscale between Windows and Mac. Do **not** expose TCP 3389 to the public Internet or forward the router RDP port.
4. Note the internal IP, Tailscale 100.x address or MagicDNS hostname of the Windows host.

Microsoft's setup instructions: https://support.microsoft.com/en-us/windows/experience/connectivity-networking/how-to-use-remote-desktop

## On the Mac

1. Install the official Microsoft Windows App from the Mac App Store.
2. Generate a restricted RDP connection profile from this repo (Python 3.10+):

       python3 -m scripts.solidworks_remote_mac --host 100.100.55.4 --output SOLIDWORKS-Remote.rdp

   Replace the example with your actual VPN IP or private host. The helper refuses public IPs and external domains. It never accepts passwords or Windows login secrets.
3. Double-click or import the new .rdp file into Windows App, and sign into your authorized Windows account. If import is unavailable in your Windows App release, use **Devices > + > Add PC** and enter the same private host manually.
4. Start SOLIDWORKS in the remote desktop. Confirm graphics and interaction with a small model first. Save projects to the Windows host or a deliberate, securely configured file sync solution.

Microsoft's Mac Windows App steps: https://learn.microsoft.com/en-us/windows-app/get-started-connect-devices-desktops-apps?pivots=remote-pc

### Security and limitations

The generated RDP profile requires credential prompts and certificate validation. It intentionally disables drive, printer, smartcard and microphone redirection, and does not embed credentials. Do not bypass certificate warnings or expose RDP on a public IP. The Windows App feature is a remote desktop experience; model computation stays on Windows. SOLIDWORKS's certified GPU guidance still applies.

For native macOS execution, return to the **Wine laboratory**; that separate path remains experimental and incomplete.
