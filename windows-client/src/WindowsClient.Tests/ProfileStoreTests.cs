using WindowsClient.Core.Models;
using WindowsClient.Infrastructure.Storage;

namespace WindowsClient.Tests;

public sealed class ProfileStoreTests
{
    [Fact]
    public async Task SaveAsync_ShouldCreateSingleConfigFile()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var store = new JsonProfileStore(root);
        var config = new ClientConfigModel();
        config.Profiles.Add(new ProfileModel
        {
            Name = "Office",
            EdgeVersionId = "v26",
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
        });

        await store.SaveAsync(config, CancellationToken.None);

        Assert.True(File.Exists(Path.Combine(root, "client-config.json")));
    }

    [Fact]
    public async Task SaveAsync_ShouldCreateBackupWhenOverwriting()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var store = new JsonProfileStore(root);
        var config = new ClientConfigModel();
        config.Profiles.Add(new ProfileModel
        {
            Name = "Office",
            EdgeVersionId = "v26",
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
        });

        await store.SaveAsync(config, CancellationToken.None);
        await store.SaveAsync(config, CancellationToken.None);

        Assert.True(Directory.Exists(Path.Combine(root, "backups")));
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(root, "backups")));
    }
}
