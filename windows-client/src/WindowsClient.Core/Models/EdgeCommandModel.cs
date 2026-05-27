namespace WindowsClient.Core.Models;

public sealed class EdgeCommandModel
{
    public string ExecutablePath { get; set; } = string.Empty;

    public List<string> Arguments { get; set; } = new();

    public string RawPreview { get; set; } = string.Empty;

    public string MaskedPreview { get; set; } = string.Empty;
}
