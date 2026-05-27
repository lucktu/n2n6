using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using WindowsClient.Core.Models;

namespace WindowsClient.App.ViewModels;

public sealed class MainWindowViewModel : INotifyPropertyChanged
{
    private ProfileModel? selectedProfile;
    private string currentStatus = "idle";
    private string activeProfileName = "none";
    private string selectedVersionName = "not selected";
    private string resolvedBinaryPath = "windows-client/bin/<version>/edge.exe";
    private string statusSummary = "No active connection. Select a profile and connect.";

    public MainWindowViewModel()
    {
        Profiles = new ObservableCollection<ProfileModel>
        {
            new() { Name = "Office", Community = "ops", SupernodeHost = "vpn.example.com", EdgeVersionId = "v26" },
            new() { Name = "Lab", Community = "lab", SupernodeHost = "lab.example.com", EdgeVersionId = "v3" },
        };

        Diagnostics = new ObservableCollection<DiagnosticItemViewModel>
        {
            new() { Title = "Edge binary", Status = "Pass", Reason = "Shell scaffold loaded.", Suggestion = "Replace with real diagnostics service next." },
            new() { Title = "TAP adapter", Status = "Warning", Reason = "No runtime TAP scan yet.", Suggestion = "Implement diagnostics service." },
        };

        LogsText = "Windows client shell initialized.";
        ProfileDetailsText = "Select a profile to see details here.";

        NewProfileCommand = new RelayCommand(() => StatusSummary = "New profile wizard is not wired yet.");
        EditProfileCommand = new RelayCommand(() => StatusSummary = SelectedProfile is null ? "Select a profile first." : $"Edit profile: {SelectedProfile.Name}");
        DeleteProfileCommand = new RelayCommand(() => StatusSummary = SelectedProfile is null ? "Select a profile first." : $"Delete profile: {SelectedProfile.Name}");
        ConnectSelectedCommand = new RelayCommand(ConnectSelectedProfile);
        DisconnectCommand = new RelayCommand(DisconnectProfile);
        ReconnectCommand = new RelayCommand(ReconnectProfile);

        SelectedProfile = Profiles.FirstOrDefault();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public event EventHandler? TrayStateChanged;

    public ObservableCollection<ProfileModel> Profiles { get; }

    public ObservableCollection<DiagnosticItemViewModel> Diagnostics { get; }

    public RelayCommand NewProfileCommand { get; }

    public RelayCommand EditProfileCommand { get; }

    public RelayCommand DeleteProfileCommand { get; }

    public RelayCommand ConnectSelectedCommand { get; }

    public RelayCommand DisconnectCommand { get; }

    public RelayCommand ReconnectCommand { get; }

    public ProfileModel? SelectedProfile
    {
        get => selectedProfile;
        set
        {
            if (SetField(ref selectedProfile, value))
            {
                SelectedVersionName = value?.EdgeVersionId ?? "not selected";
                ResolvedBinaryPath = value is null ? "windows-client/bin/<version>/edge.exe" : $"windows-client/bin/{value.EdgeVersionId}/edge.exe";
                ProfileDetailsText = value is null
                    ? "Select a profile to see details here."
                    : $"Name: {value.Name}\nCommunity: {value.Community}\nSupernode: {value.SupernodeHost}\nVersion: {value.EdgeVersionId}\nResolved path: {ResolvedBinaryPath}";
            }
        }
    }

    public string CurrentStatus
    {
        get => currentStatus;
        private set => SetField(ref currentStatus, value, notifyTray: true);
    }

    public string ActiveProfileName
    {
        get => activeProfileName;
        private set => SetField(ref activeProfileName, value, notifyTray: true);
    }

    public string SelectedVersionName
    {
        get => selectedVersionName;
        private set => SetField(ref selectedVersionName, value);
    }

    public string ResolvedBinaryPath
    {
        get => resolvedBinaryPath;
        private set => SetField(ref resolvedBinaryPath, value);
    }

    public string StatusSummary
    {
        get => statusSummary;
        set => SetField(ref statusSummary, value);
    }

    public string LogsText { get; private set; }

    public string ProfileDetailsText { get; private set; }

    private void ConnectSelectedProfile()
    {
        if (SelectedProfile is null)
        {
            StatusSummary = "No profile selected.";
            return;
        }

        CurrentStatus = "running";
        ActiveProfileName = SelectedProfile.Name;
        SelectedVersionName = SelectedProfile.EdgeVersionId;
        ResolvedBinaryPath = $"windows-client/bin/{SelectedProfile.EdgeVersionId}/edge.exe";
        StatusSummary = $"Connected using profile {SelectedProfile.Name}.";
        LogsText += $"\nConnected profile {SelectedProfile.Name}.";
        OnPropertyChanged(nameof(LogsText));
    }

    private void DisconnectProfile()
    {
        CurrentStatus = "idle";
        ActiveProfileName = "none";
        StatusSummary = "Disconnected current connection.";
        LogsText += "\nDisconnected current connection.";
        OnPropertyChanged(nameof(LogsText));
    }

    private void ReconnectProfile()
    {
        if (SelectedProfile is null)
        {
            StatusSummary = "No profile selected.";
            return;
        }

        CurrentStatus = "restarting";
        StatusSummary = $"Reconnecting profile {SelectedProfile.Name}.";
        LogsText += $"\nReconnecting profile {SelectedProfile.Name}.";
        OnPropertyChanged(nameof(LogsText));
        ConnectSelectedProfile();
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null, bool notifyTray = false)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);

        if (notifyTray)
        {
            TrayStateChanged?.Invoke(this, EventArgs.Empty);
        }

        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public sealed class DiagnosticItemViewModel
{
    public string Title { get; set; } = string.Empty;

    public string Status { get; set; } = string.Empty;

    public string Reason { get; set; } = string.Empty;

    public string Suggestion { get; set; } = string.Empty;
}
