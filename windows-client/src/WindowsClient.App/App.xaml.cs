using System.Windows;
using Forms = System.Windows.Forms;
using WindowsClient.App.ViewModels;

namespace WindowsClient.App;

public partial class App : System.Windows.Application
{
    private Forms.NotifyIcon? notifyIcon;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var viewModel = new MainWindowViewModel();
        var window = new MainWindow
        {
            DataContext = viewModel,
        };

        MainWindow = window;
        ConfigureTray(window, viewModel);
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        notifyIcon?.Dispose();
        base.OnExit(e);
    }

    private void ConfigureTray(MainWindow window, MainWindowViewModel viewModel)
    {
        notifyIcon = new Forms.NotifyIcon
        {
            Text = "Windows Client",
            Visible = true,
            Icon = System.Drawing.SystemIcons.Application,
            ContextMenuStrip = BuildTrayMenu(window, viewModel),
        };

        notifyIcon.DoubleClick += (_, _) => RestoreWindow(window);
    }

    private Forms.ContextMenuStrip BuildTrayMenu(MainWindow window, MainWindowViewModel viewModel)
    {
        var menu = new Forms.ContextMenuStrip();

        var statusItem = new Forms.ToolStripMenuItem($"Status: {viewModel.CurrentStatus}") { Enabled = false };
        var activeProfileItem = new Forms.ToolStripMenuItem($"Active: {viewModel.ActiveProfileName}") { Enabled = false };
        var connectItem = new Forms.ToolStripMenuItem("Connect current selected profile");
        var disconnectItem = new Forms.ToolStripMenuItem("Disconnect current connection");
        var openMainWindowItem = new Forms.ToolStripMenuItem("Open main window");
        var exitItem = new Forms.ToolStripMenuItem("Exit");

        connectItem.Click += (_, _) => viewModel.ConnectSelectedCommand.Execute(null);
        disconnectItem.Click += (_, _) => viewModel.DisconnectCommand.Execute(null);
        openMainWindowItem.Click += (_, _) => RestoreWindow(window);
        exitItem.Click += (_, _) => Shutdown();

        viewModel.TrayStateChanged += (_, _) =>
        {
            statusItem.Text = $"Status: {viewModel.CurrentStatus}";
            activeProfileItem.Text = $"Active: {viewModel.ActiveProfileName}";
        };

        menu.Items.Add(statusItem);
        menu.Items.Add(activeProfileItem);
        menu.Items.Add(connectItem);
        menu.Items.Add(disconnectItem);
        menu.Items.Add(openMainWindowItem);
        menu.Items.Add(exitItem);

        return menu;
    }

    private static void RestoreWindow(Window window)
    {
        window.Show();
        window.WindowState = WindowState.Normal;
        window.Activate();
    }
}

