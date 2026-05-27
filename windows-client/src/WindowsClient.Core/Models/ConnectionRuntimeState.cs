namespace WindowsClient.Core.Models;

public sealed class ConnectionRuntimeState
{
    public Guid? SelectedProfileId { get; set; }

    public Guid? ActiveProfileId { get; set; }

    public Guid? PendingProfileId { get; set; }

    public string Status { get; set; } = "idle";
}
