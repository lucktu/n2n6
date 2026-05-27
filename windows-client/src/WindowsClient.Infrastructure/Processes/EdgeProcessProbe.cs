namespace WindowsClient.Infrastructure.Processes;

public class EdgeProcessProbe
{
    public virtual Task<(bool IsValid, string VersionText, string Error)> ProbeAsync(string executablePath, CancellationToken cancellationToken)
    {
        return Task.FromResult((true, string.Empty, string.Empty));
    }
}
