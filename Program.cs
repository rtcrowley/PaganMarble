using System;
using System.Linq;
using System.Diagnostics;
using System.Management;
using System.Security.Principal;
using Microsoft.Win32;


namespace PaganMarble
{
    class Program
    {
        public static void PMheader()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("-----------------------  PaganMarble - Malicious Port Monitor Detection ---------------------");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(@"            __      `;.                         	            		");
            Console.WriteLine(@"          /' /\   ,   \                     			                ");
            Console.WriteLine(@"        /   |v-|      `;                      	   ________________     ");
            Console.WriteLine(@"       (    |_,| ,     `,                    	 _/_____________##/|    ");
            Console.WriteLine(@"        )  , \ '       `:                       /___________/__#//||    ");
            Console.WriteLine(@"       |    """"""""----,__,_.____,_*              |===        |----| ||    ");
            Console.WriteLine(@"       ;      _     |--,_;                     | Evil Port |   ô| ||	");
            Console.WriteLine(@"      ,     ,' `'---'  ,:                      |__Monitor__|   ô| ||	");
            Console.WriteLine(@"      |    ,  : /,     ,'                      | ||/.'---.||    | ||	");
            Console.WriteLine(@"      |       ,/'     ,;                       |-||/_____\||-.  | |´	");
            Console.WriteLine(@"      |   '   :|  ,   /'               	       |_||=======||_|__|/  	");
            Console.WriteLine(@"      ,        |    ,;                					                ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"-------------------------------------------------------------------------------------------");
            Console.ResetColor();
        }

        public static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }



        //////////////////////////////////
        ////////  Persistence Chk   ////// 
        //////////////////////////////////
        public static void PmPersistence()
        {
            Console.ForegroundColor = ConsoleColor.DarkMagenta;
            Console.WriteLine("------------------------  Starting Port Monitor Persistence Check -------------------------");
            Console.WriteLine("[*] NOTE: Just because the company name in fileinfo is Microsoft does not 100% mean it's legit.");
            Console.WriteLine(@"-------------------------------------------------------------------------------------------");
            Console.ResetColor();

            String appKey = @"SYSTEM\CurrentControlSet\Control\Print\Monitors\";
            using (Microsoft.Win32.RegistryKey skey = Registry.LocalMachine.OpenSubKey(appKey))
            {
                if (skey == null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine("      [-] No Monitors Exist..?");
                }
                else
                {
                    var aSubKey = 0;
                    foreach (String skeyName in skey.GetSubKeyNames())
                    {

                        string monitorSkey = @"SYSTEM\CurrentControlSet\Control\Print\Monitors\" + skeyName;
                        using (RegistryKey zkey = Registry.LocalMachine.OpenSubKey(monitorSkey))
                        {
                            Object o = zkey.GetValue("Driver");
                            if (o != null)
                            {
                                String blah = o.ToString();
                                String mDll = @"C:\Windows\System32\" + blah;

                                try
                                {
                                    FileVersionInfo sdll = FileVersionInfo.GetVersionInfo(mDll);

                                    if (sdll == null)
                                    {
                                        Console.WriteLine("DLL " + mDll + " does not have any Version Info!");

                                    }
                                    else
                                    {
                                        String dllCo = sdll.CompanyName;

                                        if (dllCo != "Microsoft Corporation")
                                        {
                                            Console.ForegroundColor = ConsoleColor.Yellow;
                                            Console.WriteLine("[-] DLL is not by Microsoft Corporation!");
                                            Console.WriteLine("   [+] Registry key: HKLM" + monitorSkey);
                                            Console.WriteLine("   [+] DLL Name: " + blah);
                                            Console.WriteLine("   [+] DLL Version info: " + sdll.FileVersion);
                                            Console.WriteLine("   [+] DLL Company Name: " + sdll.CompanyName);
                                            Console.ResetColor();
                                        }
                                        else
                                        {
                                            Console.ForegroundColor = ConsoleColor.Cyan;
                                            Console.WriteLine("[+] Success - DLL is in System32 with Microsoft Corporation as Company Name");
                                            Console.ForegroundColor = ConsoleColor.DarkGray;
                                            Console.WriteLine("   [+] Registry key: HKLM" + monitorSkey);
                                            Console.WriteLine("   [+] DLL Name: " + blah);
                                            Console.WriteLine("   [+] DLL Version info: " + sdll.FileVersion);
                                            Console.WriteLine("   [+] DLL Company Name: " + sdll.CompanyName);
                                            Console.ResetColor();
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("[!] Cannot find DLL in System32!");
                                    Console.WriteLine("   [*] Registry key: HKLM" + monitorSkey);
                                    Console.WriteLine("   [*] DLL in question: " + blah);
                                    Console.ResetColor();
                                }
                            }
                        }
                        Console.WriteLine("");
                        aSubKey = aSubKey + 1;
                    }
                    if (aSubKey == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkCyan;
                        Console.WriteLine("      [-] No SubKeys detected.");

                    }
                }
            }
        }

        //////////////////////////////////
        ////////  Live Chk    //////////// 
        //////////////////////////////////
        public static void PmLive()
        {

            Console.ForegroundColor = ConsoleColor.DarkMagenta;
            Console.WriteLine("------------------------  Starting Port Monitor Live Check  -------------------------");
            Console.WriteLine("[+] Searching Processes with a Parent Process of 'spoolsv'");
            Console.ResetColor();



            var spools = Process.GetProcessesByName("spoolsv").Single();
            var id = spools.Id;
            //Console.WriteLine(id);


            ManagementClass mngcls = new ManagementClass("Win32_Process");
            int i = 0;
            int bad = 0;

            Console.Write("      ");

            foreach (ManagementObject instance in mngcls.GetInstances())
            {
                
                try
                {
                    
                    //Console.Write("ID: " + instance["ProcessId"]);
                    var myId = instance["ProcessId"];
                    var query = string.Format("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", myId);
                    var search = new ManagementObjectSearcher("root\\CIMV2", query);
                    var results = search.Get().GetEnumerator();
                    results.MoveNext();
                    var queryObj = results.Current;
                    var parentId = (uint)queryObj["ParentProcessId"];
                    var parent = Process.GetProcessById((int)parentId);
                    var parentName = parent.ProcessName;

                    if (parentName == "spoolsv")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("");
                        Console.WriteLine("[*] ALERT: Process PPID is spoolsv!");
                        Console.WriteLine("       PID           : " + myId);
                        Console.WriteLine("       Parent Name   : " + parentName);
                        Console.ResetColor();
                        bad = bad + 1;
                        Console.Write("      ");
                    }
                    else
                    {                                               
                        if (i % 6 == 0)
                        {
                            if (i % 20 == 0)
                            {
                                Console.WriteLine("");
                                Console.Write("      ");
                            }
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.Write(" * ");
                            Console.ResetColor();
                        }
                        i = i + 1;
                    }
                }
                catch (Exception ex)
                {
                    //proc is not running..maybe
                }

                
            }
            if (bad == 0)
            {
                Console.WriteLine("\n");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("[+] Great! No procs with 'spoolsv' as the parent proc.");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Be Advised: 1 or more procs with 'spoolsv' as the parent proc.");
                Console.ResetColor();
            }
        }

        //////////////////////////////////
        ////////  MAIN        //////////// 
        //////////////////////////////////
        static void Main(string[] args)
        {
            PMheader();

            if (IsAdministrator() != true)                
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("[!] NOT Running as Administrator!" + "\n");
                Console.ResetColor();
                Environment.Exit(0);
            }

            PmPersistence();
            PmLive();

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("-------------------------------------  COMPLETE -------------------------------------");
            Console.ResetColor();
        }

    }
}