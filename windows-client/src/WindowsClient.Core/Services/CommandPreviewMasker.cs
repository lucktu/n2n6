namespace WindowsClient.Core.Services;

public sealed class CommandPreviewMasker
{
    public string MaskSecret(string preview, string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return preview;
        }

        return preview.Replace(secret, "***", StringComparison.Ordinal);
    }
}
