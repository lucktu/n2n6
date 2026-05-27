namespace WindowsClient.Core.Models;

public sealed class VersionInfoModel
{
    public string Id { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string RelativePath { get; set; } = string.Empty;

    public string DetectedVersionText { get; set; } = string.Empty;

    public bool IsValid { get; set; }

    public string LastScanError { get; set; } = string.Empty;
}
