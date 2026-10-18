// Windows-only protected recipient; production deliberately DENIED until
// real operator key custody, independent witness and REVIEW are provisioned.
// --ci-one-shot writes ONE inert file on ephemeral GitHub-hosted Windows ONLY.
// --service implements real Windows ServiceBase lifecycle but currently
// rejects all production effects. Never run this as an administrator/worker.
using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Neurofactory.WindowsReceiver;

internal sealed class ReceiverConfig
{
    public string PipeName { get; set; } = "";
    public string ScratchRoot { get; set; } = "";
    public string WorkerSid { get; set; } = "";
    public string OwnerPublicSpkiBase64 { get; set; } = "";
    public string TaskId { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string SourceSha40 { get; set; } = "";
    public string AllowedTarget { get; set; } = "";
}

internal sealed class ProtectedService : ServiceBase
{
    public ProtectedService()
    {
        ServiceName = "NeurofactoryReceiver";
        CanStop = true;
        CanShutdown = true;
    }
    // Installed service intentionally has NO ability to receive/write files:
    // owner-signed production key custody and durable off-machine witness
    // have not been provisioned or independently accepted.
    protected override void OnStart(string[] args) =>
        EventLogSafe("LIVE_EXECUTION_BLOCKED_NO_INDEPENDENT_OPERATOR_ROOT");
    protected override void OnStop() =>
        EventLogSafe("RECEIVER_STOPPED_WITHOUT_PRODUCTION_EFFECT");
    private static void EventLogSafe(string message) => Console.Error.WriteLine(message);
}

internal static class Program
{
    private const int MaxJson = 16384;
    private const int MaxContent = 512;
    private const string BodySchema = "neurofactory.windows.core_signed_scratch.v1";
    private static bool FixtureEnabled =>
        OperatingSystem.IsWindows()
        && Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true"
        && Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") == "github-hosted"
        && Environment.GetEnvironmentVariable("NF_WINDOWS_RECEIVER_CI_ONLY") == "1";

    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
            return 3;
        if (args.Length == 1 && args[0] == "--service")
        {
            ServiceBase.Run(new ProtectedService());
            return 0;
        }
        if (args.Length != 2 || args[0] != "--ci-one-shot" || !FixtureEnabled)
            return 3;
        try
        {
            var cfgPath = Path.GetFullPath(args[1]);
            if (!File.Exists(cfgPath) || IsReparse(cfgPath))
                throw new InvalidOperationException("CI config missing or substituted");
            var cfg = JsonSerializer.Deserialize<ReceiverConfig>(
                File.ReadAllBytes(cfgPath)) ?? throw new InvalidOperationException();
            ValidateConfig(cfg);
            ServeOnce(cfg);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("CI_RECEIVER_DENIED: " + ex.GetType().Name);
            return 3;
        }
    }

    private static bool IsReparse(string path) =>
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    private static void ValidateConfig(ReceiverConfig cfg)
    {
        if (!Regex.IsMatch(cfg.PipeName, @"\Anf-ci-[a-f0-9]{16}\z")
            || !Regex.IsMatch(cfg.TaskId, @"\ANF-DEV-05-Q[0-9]{3}\z")
            || !Regex.IsMatch(cfg.ProjectId, @"\A[a-z][a-z0-9-]{2,39}\z")
            || !Regex.IsMatch(cfg.SourceSha40, @"\A[a-f0-9]{40}\z")
            || cfg.AllowedTarget != "core-e2e-proof.txt")
            throw new InvalidOperationException("CI scope must be fixed and bounded");
        if (!Directory.Exists(cfg.ScratchRoot) || IsReparse(cfg.ScratchRoot)
            || !Path.GetFullPath(cfg.ScratchRoot)
               .StartsWith(Path.GetFullPath(Path.GetTempPath()),
                            StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only disposable temp sandbox accepted");
        _ = new SecurityIdentifier(cfg.WorkerSid);
        var pub = Convert.FromBase64String(cfg.OwnerPublicSpkiBase64);
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(pub, out int read);
        if (read != pub.Length || key.KeySize != 256)
            throw new InvalidOperationException("Expected exact P-256 key");
    }

    private static PipeSecurity PipeAcl(string clientSid)
    {
        var p = new PipeSecurity();
        p.SetAccessRuleProtection(true, false);
        var worker = new SecurityIdentifier(clientSid);
        var self = WindowsIdentity.GetCurrent().User
                   ?? throw new InvalidOperationException("Receiver identity missing");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        // No Everyone, Authenticated Users, Administrators or anonymous grants.
        p.AddAccessRule(new PipeAccessRule(worker, PipeAccessRights.ReadWrite,
                                           AccessControlType.Allow));
        p.AddAccessRule(new PipeAccessRule(self, PipeAccessRights.FullControl,
                                           AccessControlType.Allow));
        p.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl,
                                           AccessControlType.Allow));
        return p;
    }

    private static void ServeOnce(ReceiverConfig cfg)
    {
        using var pipe = NamedPipeServerStreamAcl.Create(
            cfg.PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.None, 16384, 4096, PipeAcl(cfg.WorkerSid));
        Console.WriteLine("NF_WIN_RECEIVER_LISTENING_TEST_ONLY");
        Console.Out.Flush();
        pipe.WaitForConnection();

        string clientSid = "";
        try
        {
            pipe.RunAsClient(() =>
            {
                clientSid = WindowsIdentity.GetCurrent(true).User?.Value ?? "";
            });
        }
        catch { clientSid = ""; }
        object answer;
        if (clientSid != cfg.WorkerSid)
        {
            answer = Denied();
        }
        else
        {
            try
            {
                using var request = ReadFramed(pipe);
                answer = ProcessFixtureRequest(cfg, request.RootElement);
            }
            catch { answer = Denied(); }
        }
        SendFramed(pipe, answer);
        pipe.WaitForPipeDrain();
    }

    private static JsonDocument ReadFramed(Stream stream)
    {
        Span<byte> header = stackalloc byte[4];
        stream.ReadExactly(header);
        int len = BinaryPrimitives.ReadInt32BigEndian(header);
        if (len < 1 || len > MaxJson)
            throw new InvalidDataException("Oversize or negative request");
        byte[] data = new byte[len];
        stream.ReadExactly(data);
        return JsonDocument.Parse(data,
            new JsonDocumentOptions { MaxDepth = 5, AllowTrailingCommas = false });
    }

    private static void SendFramed(Stream stream, object message)
    {
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(message);
        if (data.Length > 4096) throw new InvalidDataException();
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, data.Length);
        stream.Write(header);
        stream.Write(data);
        stream.Flush();
    }

    private static object Denied() => new {
        status = "DENIED_OR_UNKNOWN_MANUAL_STOP",
        file_sha256 = "",
        live_execution_allowed = false,
        automatic_retry_allowed = false
    };

    private static JsonElement Strict(JsonElement obj, string name)
    {
        if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty(name, out var val))
            throw new InvalidDataException();
        return val;
    }

    private static string Field(JsonElement obj, string key) =>
        Strict(obj, key).GetString() ?? throw new InvalidDataException();

    private static object ProcessFixtureRequest(ReceiverConfig cfg, JsonElement request)
    {
        if (request.ValueKind != JsonValueKind.Object
            || request.EnumerateObject().Count() != 4
            || Field(request, "schema") != "nf.windows.receiver.request.v1")
            return Denied();
        string rawBody = Field(request, "body_base64");
        string rawSignature = Field(request, "owner_signature_base64");
        string rawContent = Field(request, "content_base64");
        if (rawBody.Length > 4096 || rawContent.Length > 1500 ||
            rawSignature.Length > 120)
            return Denied();
        byte[] bodyBytes = Convert.FromBase64String(rawBody);
        byte[] signature = Convert.FromBase64String(rawSignature);
        byte[] content = Convert.FromBase64String(rawContent);
        if (signature.Length != 64 || content.Length < 1 || content.Length > MaxContent
            || bodyBytes.Length > 4096)
            return Denied();

        using var owner = ECDsa.Create();
        owner.ImportSubjectPublicKeyInfo(
            Convert.FromBase64String(cfg.OwnerPublicSpkiBase64), out _);
        if (!owner.VerifyData(bodyBytes, signature, HashAlgorithmName.SHA256,
                              DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            return Denied();

        using var document = JsonDocument.Parse(bodyBytes,
            new JsonDocumentOptions { MaxDepth = 3 });
        var body = document.RootElement;
        if (body.ValueKind != JsonValueKind.Object || body.EnumerateObject().Count() != 12
            || Field(body, "schema") != BodySchema
            || Field(body, "task_id") != cfg.TaskId
            || Field(body, "project_id") != cfg.ProjectId
            || Field(body, "source_sha40") != cfg.SourceSha40
            || Field(body, "target") != cfg.AllowedTarget
            || Field(body, "mode") != "CORE_SIGNED_SCRATCH_TEST_ONLY"
            || Strict(body, "model_invoked").ValueKind != JsonValueKind.False
            || Strict(body, "owner_confirmed").ValueKind != JsonValueKind.True
            || Field(body, "content_sha256") !=
                Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant()
            || !Regex.IsMatch(Field(body, "operation_id"), @"\Aop-[a-f0-9]{24}\z")
            || !Regex.IsMatch(Field(body, "worker_id"), @"\Aworker-[a-z0-9-]{4,25}\z"))
            return Denied();
        long expires = Strict(body, "expires_unix").GetInt64();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (expires <= now || expires > now + 120)
            return Denied();

        // No control of path from request: fixed file name, pinned to CI
        // config, scratch directory checked for reparse points.
        var root = Path.GetFullPath(cfg.ScratchRoot);
        if (IsReparse(root)) return Denied();
        var intent = Path.Combine(root, "nf-effect-unknown.receipt");
        var target = Path.Combine(root, cfg.AllowedTarget);
        if (File.Exists(intent) || File.Exists(target) || IsReparseIfExists(target))
            return Denied();
        var receipt = Encoding.ASCII.GetBytes(
            "UNKNOWN_MANUAL_STOP|" + Field(body, "operation_id") + "|" +
            Field(body, "content_sha256"));
        // Exclusive durable UNKNOWN before effect: if crash after this
        // reservation, duplicate is forbidden even if target absent.
        using (var marker = new FileStream(
            intent, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            4096, FileOptions.WriteThrough))
        {
            marker.Write(receipt);
            marker.Flush(true);
        }
        if (FixtureEnabled &&
            Environment.GetEnvironmentVariable("NF_WIN_CI_CRASH_AFTER_INTENT") == "1")
            throw new IOException("CI_INJECTED_CRASH_AFTER_UNKNOWN");
        using (var file = new FileStream(
            target, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            4096, FileOptions.WriteThrough))
        {
            file.Write(content);
            file.Flush(true);
        }
        return new {
            status = "WIN_CORE_TO_PROTECTED_SCRATCH_ONE_FILE_TEST_ONLY",
            file_sha256 = Field(body, "content_sha256"),
            live_execution_allowed = false,
            automatic_retry_allowed = false
        };
    }

    private static bool IsReparseIfExists(string path) =>
        (File.Exists(path) || Directory.Exists(path)) && IsReparse(path);
}
