using System;
using System.Windows.Forms;
using System.Management;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Security.Principal;
using System.Diagnostics;
using WUApiLib;
using System.Runtime.InteropServices;
using System.Management.Automation;

namespace Surprise
{
    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {       
            if (!IsAdministrator())
            {                
                Console.Error.WriteLine("### ERROR! ### Please right click this file and Run as Administrator.");
                Console.WriteLine("Press any key to quit...");
                Console.ReadKey();
                System.Environment.Exit(1);
            }
            Console.Clear();

            Process p = Process.GetCurrentProcess();
            ShowWindow(p.MainWindowHandle, 3); //SW_MAXIMIZE = 3
            
            Console.WriteLine("### " + DateTime.Now + Environment.NewLine);
            Console.WriteLine("### Please select folder to save logs:");

            FolderBrowserDialog fbd = new FolderBrowserDialog();
            if (fbd.ShowDialog() == DialogResult.OK)
            {
                var saveFolder = fbd.SelectedPath;                
                Console.WriteLine("### Saving to " + saveFolder);           
                
                GetUserLogs(saveFolder);
                CaptureProcess("systeminfo", saveFolder + "\\" + Environment.MachineName + "_Systeminfo.txt");
                GetPatches(saveFolder + "\\" + Environment.MachineName + "_Patches.csv");
                GetAVStatus(saveFolder + "\\" + Environment.MachineName + "_AV.txt");                
                Console.WriteLine("### Done!" + Environment.NewLine);
                Console.WriteLine("(Press any key to quit)");
                CaptureScreen(saveFolder + "\\" + Environment.MachineName + "_Screenshot.png");
                Console.ReadKey();
            }
        }

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(System.IntPtr hWnd, int cmdShow);

        public static void GetUserLogs(string saveFolder)
        {
            Console.WriteLine("### Getting local admin logons events for " + Environment.MachineName);

            SelectQuery query = new SelectQuery("Win32_UserAccount");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                string userName = envVar["Name"].ToString();
                Console.WriteLine("*** " + userName);
                GetLogs(userName, saveFolder + "\\" + Environment.MachineName + "_" + userName + ".csv");
            }
        }

        public static void GetLogs(string userName, string savePath)
        {
            using (var w = new StreamWriter(savePath))
            {
                w.WriteLine("\"ERID\",\"Time\",\"EID\",\"Task\",\"Username\"");
                string query = "*[EventData[Data[@Name='SubjectUserName'] and (Data='" + userName + "')]]";
                EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, query);
                try
                {
                    EventLogReader logReader = new EventLogReader(eventsQuery);
                    for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                    {                        
                        var line = string.Format("{0},{1},{2},{3},{4}", eventdetail.RecordId.ToString(), eventdetail.TimeCreated, eventdetail.Id, eventdetail.TaskDisplayName, userName);
                        w.WriteLine(line);
                        w.Flush();
                    }
                }
                catch (EventLogNotFoundException e)
                {
                    Console.WriteLine(e + " Error while reading the event logs");
                    return;
                }
            }
        }

        public static void CaptureProcess(string cmd, string savePath)
        {
            Console.WriteLine("### Getting system info...");

            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = cmd,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            using (var w = new StreamWriter(savePath))
            {
                proc.Start();
                while (!proc.StandardOutput.EndOfStream)
                {
                    string line = proc.StandardOutput.ReadLine();                    
                    w.WriteLine(line);
                    w.Flush();
                }
            }
        }

        public static void GetPatches(string savePath)
        {
            Console.WriteLine("### Getting patch status...");

            /*using (var w = new StreamWriter(savePath))
            {
                Type t = Type.GetTypeFromProgID("Microsoft.Update.Session");
                UpdateSession session = (UpdateSession)Activator.CreateInstance(t);
                IUpdateSearcher updateSearcher = session.CreateUpdateSearcher();
                int count = updateSearcher.GetTotalHistoryCount();
                IUpdateHistoryEntryCollection history = updateSearcher.QueryHistory(0, count);
                for (int i = 0; i < count; ++i)
                {
                    //Console.WriteLine(string.Format("Title: {0}\tSupportURL: {1}\tDate: {2}\tResult Code: {3}\tDescription: {4}\r\n", history[i].Title, history[i].SupportUrl, history[i].Date, history[i].ResultCode, history[i].Description));
                    var line = string.Format("{0},{1}", history[i].Date, history[i].Title);
                    w.WriteLine(line);
                    w.Flush();
                }
            }*/

            try
            {
                using (PowerShell PowerShellInstance = PowerShell.Create())
                {
                    PowerShellInstance.AddScript("get-hotfix | Export-Csv " + savePath);
                    IAsyncResult result = PowerShellInstance.BeginInvoke();
                    while (result.IsCompleted == false)
                    {
                    }
                    Console.WriteLine("### Getting patch status done!");
                }
            }
            catch
            {
                Console.WriteLine("*** Error getting patch status. Get screenshot manually?");
            }                
        }

        public static void GetAVStatus(string savePath)
        {
            Console.WriteLine("### Getting AV info...");

            try
            {
                using (var w = new StreamWriter(savePath))
                {
                    var path = string.Format(@"\\{0}\root\SecurityCenter2", Environment.MachineName);
                    var searcher = new ManagementObjectSearcher(path, "SELECT * FROM AntivirusProduct");
                    var instances = searcher.Get();
                    string AvState;
                    string AvUpToDate;
                    foreach (ManagementObject item in instances)
                    {
                        //Console.WriteLine(item["productUptoDate"]);
                        string s = item["productState"].ToString();
                        int n = int.Parse(s); // to int
                        string AvStatus = n.ToString("X"); // to hex
                                                           //Console.WriteLine(AvStatus);
                                                           //Console.WriteLine(AvStatus.Substring(1, 2));
                        if (AvStatus.Substring(1, 2) == "10" || AvStatus.Substring(1, 2) == "11")
                            AvState = "Enabled";
                        else
                            AvState = "Disabled";

                        if (AvStatus.Substring(3, 2) == "00")
                            AvUpToDate = "Updated definitions";
                        else
                            AvUpToDate = "Outdated definitions";

                        string line = item["displayName"] + " / " + AvState + " / " + AvUpToDate;
                        w.WriteLine(line);
                        w.Flush();
                    }
                }
            }
            catch
            {
                Console.WriteLine("*** Error getting AV info. Is it installed?");
            }
        }

        public static void CaptureScreen(string savePath)
        {
            //Console.WriteLine("### Getting screenshot...");

            try
            {
                PrintScreen ps = new PrintScreen();
                ps.CaptureScreenToFile(savePath, System.Drawing.Imaging.ImageFormat.Png);
            }
            catch
            {
                Console.WriteLine("*** Error getting screenshot!");
            }
        }

        public static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
