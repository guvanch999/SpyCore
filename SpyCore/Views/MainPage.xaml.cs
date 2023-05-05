using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Windows.Controls;

using SpyCore.ViewModels;
using VirusTotalNet.Results;
using VirusTotalNet;
using System.Collections.ObjectModel;
using SpyCore.Models;
using ControlzEx.Standard;
using VirusTotalNet.ResponseCodes;
using System.Windows.Forms;
using System.Net;
using static SpyCore.Views.MainPage;

namespace SpyCore.Views
{
    public class AvCollection
    {
        public string AV { get; set; }
        public string Virus { get; set; }
        public string scanDate { get; set; }
        public string Threat { get; set; }
    }
    public class ResultCollection : ObservableCollection<sResults> { }
    public partial class MainPage : Page
    {
        public class sResults
        {
            public int item { get; set; }
            public string Anti__Virus__Vendor { get; set; }
            public string Detected__as__Virus { get; set; }
            public string Date__Of__First__Scan { get; set; }
            public string Threat { get; set; }
            // public string Threat { get; set; }
        }
        public IList<sResults> AvCollected { get; set; }
        public Timer ScanTimer { get => scanTimer; set => scanTimer = value; }

        public MainPage(MainViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
        }
        private static string _path;

#region Scan Logic
        private async void DoLogicString(string text)
        {
            //resultView.Items.Clear();
            byte[] virus = Encoding.ASCII.GetBytes(text);
            FileReport fr = null;
            try
            {
                fr = await ScanBytesAsync(virus);
            }
            catch (Exception e)
            {
                metroLabel3.Content = "Skaneriň çägi - minutda 4 gezek!";
                Console.Beep();
                return;
            }
            ReportStructure structure = null;
            if (fr != null)
            {
                structure = ReportStructure.FromReport(fr);
            }
            if (structure != null)
            {
                int i = 0;
                List<sResults> RES = new List<sResults>(); 
                foreach (KeyValuePair<string, bool> pair in structure.ScanResults)
                {
                    i++;
                    RES.Add(new sResults()
                    {
                        item = i, 
                        Anti__Virus__Vendor = pair.Key,
                        Detected__as__Virus = pair.Value ? "Howa" : "Ýok",
                        Date__Of__First__Scan = structure.ScanDate.ToString(),
                        //Threat = Convert.ToString(structure.VirNames)
                    });
                }
                resultView.ItemsSource = RES;
                int YesCount = 0;
                int NoCount = 0;
                foreach (bool vir in structure.ScanResults.Values)
                {
                    if (vir)
                    {
                        YesCount++;
                    }
                    else
                    {
                        NoCount++;
                    }
                }
                if (YesCount > NoCount)
                {
                    metroLabel3.Content = "Wirus tapyldy!";
                }
            }
        }
        private bool CheckInternetConnection()
        {
            try
            {
                using (var client = new WebClient())
                using (var stream = client.OpenRead("http://www.google.com"))
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }
        private string[] _vName;
        private async void DoLogicAsync(string path)
        {
            //resultView.Items.Clear();
            FileReport fr = null;
            try
            {
                _info = path;
                fr = await ScanFileAsync(path);
            }
            catch (Exception e)
            {
                metroLabel3.Content = "Skaneriň çägi - minutda 4 gezek!";
                return;
            }
            ReportStructure structure = null;
            if (fr != null)
            {
                structure = ReportStructure.FromReport(fr);
            }
            if (structure != null)
            {
                int i = 0;
                int o = -1;
                List<sResults> RES = new List<sResults>();
                foreach (KeyValuePair<string, bool> pair in structure.ScanResults)
                {
                    o = o + 1;
                    RES.Add(new sResults()
                    {
                        item = i++,
                        Anti__Virus__Vendor = pair.Key,
                        Detected__as__Virus = pair.Value ? "Howa" : "Ýok",
                        Date__Of__First__Scan = structure.ScanDate.ToString(),
                        Threat = structure.VirNames[o]
                    });
                    i = i++;
                    //Threat = vName
                }
                resultView.ItemsSource = RES;
                int YesCount = 0;
                int NoCount = 0;
                foreach (bool vir in structure.ScanResults.Values)
                {
                    if (vir)
                    {   YesCount++; }
                    else
                    {   NoCount++;  }
                }
                if ((YesCount < 19) && (YesCount > 0))
                {   metroLabel3.Content = "Potensial wirus tapyldy!"; }
                else if (YesCount > 19)
                {   metroLabel3.Content = "Wirus tapyldy!"; }
                else if (YesCount == 0)
                {   metroLabel3.Content = "Faýl arassa!"; }
            }

        }

        private async Task<FileReport> ScanBytesAsync(byte[] bytes)
        {
#region APIKEY
            VirusTotal virusTotal = new VirusTotal(Properties.Settings.Default.VTAKey);
#endregion
            virusTotal.UseTLS = true;
            FileReport report = await virusTotal.GetFileReportAsync(bytes);
            bool hasFileBeenScannedBefore = report.ResponseCode == FileReportResponseCode.Present;
            if (hasFileBeenScannedBefore)
            {
                metroLabel3.Content = "Üstünlikli skaner edildi.";
                return report;
            }
            else
            {
                ScanResult fileResult = await virusTotal.ScanFileAsync(bytes, "Eicar.txt");
                metroLabel3.Content = "Skaner dowam edýär. Takmynan 2 minut garaşyň we gaýtadan gözden geçiriň!";
                report = null;
                return report;
            }
        }
        private static string _info;
        private Timer scanTimer = new Timer();
        private async Task<FileReport> ScanFileAsync(string path)
        {
            FileInfo info = new FileInfo(path);
            VirusTotal vt = new VirusTotal(Properties.Settings.Default.VTAKey);
            vt.UseTLS = true;
            FileReport fileReport = await vt.GetFileReportAsync(info);
            bool hasFileBeenScannedBefore = fileReport.ResponseCode == FileReportResponseCode.Present;
            if (!hasFileBeenScannedBefore)
            {
                ScanResult fileResult = await vt.ScanFileAsync(info);
                button1.IsEnabled = false;
                scanTimer.Tick += new System.EventHandler(this.scanTimer_Tick);
                ScanTimer.Enabled = true;
                ScanTimer.Interval = 1000;
                ScanTimer.Start();
                return null;
            }
            else
            {
                metroLabel3.Content = "Üstünlikli skaner edildi.";
                button1.IsEnabled = true;
                return fileReport;
            }
        }
        private static int WaitTime = 120;        
        private void scanTimer_Tick(object sender, EventArgs e)
        {
            int sCount = 0;
            metroLabel3.Content = "Skaner dowam edýär. Netijeler " + WaitTime + " sekuntda taýýar bolmaly";
            WaitTime = WaitTime - 1;
            if (sCount == WaitTime)
            {
                ScanTimer.Stop();
                ScanTimer.Enabled = false;
                DoLogicAsync(_info);
            }

        }
#endregion

        private void button2_Click_1(object sender, System.Windows.RoutedEventArgs e)
        {
            OpenFileDialog k = new OpenFileDialog();
            //DialogResult result = k.ShowDialog(); // Show the dialog.
            //if (result == DialogResult.OK) // Test result.
            //{
            k.ShowDialog();
            string file = k.FileName;
            fileLocation.Text = file;
            _path = System.IO.Path.GetFullPath(file);
        }

        private void button1_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(fileLocation.Text) || string.IsNullOrEmpty(fileLocation.Text))
            {
                metroLabel3.Content = "faýl ýoly boş bolup bilmez!";
                return;
            }
            if (!File.Exists(fileLocation.Text))
            {
                metroLabel3.Content = "Görkezilen faýl ýok!";
                return;
            }
            if (!CheckInternetConnection())
            {
                metroLabel3.Content = "Internet baglanyşyk Tapylmady!";
                return;
            }
            DoLogicAsync(fileLocation.Text);
        }
    }
}
