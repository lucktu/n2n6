namespace WindowsClient.Core.Models;

public sealed class AppStateModel
{
    public Guid? SelectedProfileId { get; set; }

    public string LastActiveTab { get; set; } = "Logs";

    public bool StartMinimizedToTray { get; set; }
}
