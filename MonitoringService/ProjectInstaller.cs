using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;
using System.Linq;
using System.ServiceProcess;
using System.Threading.Tasks;

namespace MonitoringService
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : System.Configuration.Install.Installer
    {
        public ProjectInstaller()
        {
            InitializeComponent();
        }

        private void serviceInstaller1_AfterInstall(object sender, InstallEventArgs e)
        {
            (new ServiceController(this.serviceInstaller1.ServiceName)).Start();
        }

        private void serviceInstaller1_BeforeUninstall(object sender, InstallEventArgs e)
        {
            ServiceController sc = new ServiceController(this.serviceInstaller1.ServiceName);
            if (sc.Status == ServiceControllerStatus.Running)
                sc.Stop();
        }
    }
}
