using WindowsClient.Infrastructure.Versions;

namespace WindowsClient.Tests;

public sealed class VersionDiscoveryTests
{
    [Fact]
    public async Task DiscoverAsync_ShouldReturnVersionFoldersContainingEdgeExe()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "bin", "v26"));
        await File.WriteAllTextAsync(Path.Combine(root, "bin", "v26", "edge.exe"), "fake-binary");

        var service = new VersionDiscoveryService(root, probe: null);

        var versions = await service.DiscoverAsync(CancellationToken.None);

        Assert.Contains(versions, version => version.Id == "v26");
    }
}
