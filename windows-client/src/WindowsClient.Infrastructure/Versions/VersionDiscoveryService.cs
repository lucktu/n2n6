using WindowsClient.Core.Interfaces;
using WindowsClient.Core.Models;
using WindowsClient.Infrastructure.Processes;

namespace WindowsClient.Infrastructure.Versions;

public sealed class VersionDiscoveryService : IVersionDiscoveryService
{
    private readonly string rootPath;
    private readonly EdgeProcessProbe? probe;

    public VersionDiscoveryService(string rootPath, EdgeProcessProbe? probe)
    {
        this.rootPath = rootPath;
        this.probe = probe;
    }

    public async Task<IReadOnlyList<VersionInfoModel>> DiscoverAsync(CancellationToken cancellationToken)
    {
        var binPath = Path.Combine(rootPath, "bin");
        if (!Directory.Exists(binPath))
        {
            return Array.Empty<VersionInfoModel>();
        }

        var results = new List<VersionInfoModel>();
        foreach (var versionDirectory in Directory.GetDirectories(binPath))
        {
            var id = Path.GetFileName(versionDirectory);
            var executablePath = Path.Combine(versionDirectory, "edge.exe");
            if (!File.Exists(executablePath))
            {
                continue;
            }

            var model = new VersionInfoModel
            {
                Id = id,
                DisplayName = id,
                RelativePath = Path.Combine("bin", id, "edge.exe"),
                IsValid = true,
            };

            if (probe is not null)
            {
                var probeResult = await probe.ProbeAsync(executablePath, cancellationToken);
                model.IsValid = probeResult.IsValid;
                model.DetectedVersionText = probeResult.VersionText;
                model.LastScanError = probeResult.Error;
            }

            results.Add(model);
        }

        return results;
    }
}
