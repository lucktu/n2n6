using System.Text.Json;
using WindowsClient.Core.Interfaces;
using WindowsClient.Core.Models;

namespace WindowsClient.Infrastructure.Storage;

public sealed class JsonProfileStore : IProfileStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly string rootPath;
    private readonly string configPath;
    private readonly string backupPath;

    public JsonProfileStore(string rootPath)
    {
        this.rootPath = rootPath;
        configPath = Path.Combine(rootPath, "client-config.json");
        backupPath = Path.Combine(rootPath, "backups");
    }

    public async Task<ClientConfigModel> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(configPath))
        {
            return new ClientConfigModel();
        }

        await using var stream = File.OpenRead(configPath);
        var config = await JsonSerializer.DeserializeAsync<ClientConfigModel>(stream, SerializerOptions, cancellationToken);
        return config ?? new ClientConfigModel();
    }

    public async Task SaveAsync(ClientConfigModel config, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(rootPath);

        if (File.Exists(configPath))
        {
            Directory.CreateDirectory(backupPath);
            var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmssfff");
            var backupFile = Path.Combine(backupPath, $"client-config-{timestamp}.json");
            File.Copy(configPath, backupFile, overwrite: false);
        }

        var tempPath = Path.Combine(rootPath, $"client-config.{Guid.NewGuid():N}.tmp");
        await using (var stream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(stream, config, SerializerOptions, cancellationToken);
        }

        if (File.Exists(configPath))
        {
            File.Delete(configPath);
        }

        File.Move(tempPath, configPath);
    }
}
