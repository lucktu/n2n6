namespace WindowsClient.Core.Models;

public sealed class ProfileModel
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string EdgeVersionId { get; set; } = string.Empty;
    public string SupernodeHost { get; set; } = string.Empty;
    public int SupernodePort { get; set; }
    public string Community { get; set; } = string.Empty;
    public string ResolutionMode { get; set; } = "auto";
    public string TapName { get; set; } = string.Empty;
    public string IPv4AddressWithPrefix { get; set; } = string.Empty;
    public string IPv6AddressWithPrefix { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string EncryptionMode { get; set; } = string.Empty;
    public string PlaintextKey { get; set; } = string.Empty;
    public bool AcceptMulticast { get; set; }
    public bool EnableRouting { get; set; }
    public int? ManagementPort { get; set; }
    public string ExtraArgs { get; set; } = string.Empty;
    public DateTimeOffset? LastUsedAt { get; set; }
}
