
using PgpCore;

namespace SecureNet;

public static class ManifestSigning {

    public static async Task<T2> Guard<T1, T2>(
        string publicKeyResource,
        FileInfo manifest,
        Func<string, T2>? parseCallback = null,
        Func<T2, bool>? verifyCallback = null
    ) {
        var publicKey = EmbeddedResource<T1>(publicKeyResource);
        using var inputFileStream = manifest.OpenRead();
        return await Guard<T2>(publicKey, inputFileStream, parseCallback, verifyCallback);
    }

    public static async Task<T2> Guard<T1, T2>(
        string publicKeyResource,
        string manifestResource,
        Func<string, T2>? parseCallback = null,
        Func<T2, bool>? verifyCallback = null
    ) {
        var publicKey = EmbeddedResource<T1>(publicKeyResource);
        using var inputFileStream = EmbeddedResourceStream<T1>(manifestResource);
        return await Guard<T2>(publicKey, inputFileStream, parseCallback, verifyCallback);
    }

    public static async Task<T> Guard<T>(
        string publicKey,
        FileInfo manifest,
        Func<string, T>? parseCallback = null,
        Func<T, bool>? verifyCallback = null
    ) {
        using var inputFileStream = manifest.OpenRead();
        return await Guard<T>(publicKey, inputFileStream, parseCallback, verifyCallback);
    }

    public static async Task<T> Guard<T>(
        string publicKey,
        Stream manifestStream,
        Func<string, T>? parseCallback = null,
        Func<T, bool>? verifyCallback = null
    ) {
        var encryptionKeys = new EncryptionKeys(publicKey);
        var pgp = new PGP(encryptionKeys);
        using var outputStream = new MemoryStream();

        var isGoodSignature = await pgp.VerifyClearAsync(manifestStream, outputStream);
        if (!isGoodSignature)
            throw new Exception("Signature is invalid guarded with the public key!");

        outputStream.Seek(0, SeekOrigin.Begin);
        using var outputStreamReader = new StreamReader(outputStream);
        var output = outputStreamReader.ReadToEnd();

        T parsedOutput = parseCallback != null ?
            parseCallback(output) :
            DefaultParseCallback<T>(output);

        if (verifyCallback != null) {
            var isGoodManifest = verifyCallback(parsedOutput);
            if (!isGoodManifest)
                throw new Exception("Manifest verification failed!");
        }

        return parsedOutput;
    }

    private static Stream EmbeddedResourceStream<T>(string resource) {
        var assembly = typeof(T).Assembly;
        var resourceStream = assembly.GetManifestResourceStream(resource);
        if (resourceStream == null)
            throw new Exception($"Resource '{resource}' could not be read from assembly.");
        return resourceStream;
    }

    private static string EmbeddedResource<T>(string resource) {
        var resourceStream = EmbeddedResourceStream<T>(resource);
        using var readStream = new StreamReader(resourceStream);
        return readStream.ReadToEnd();
    }

    private static T DefaultParseCallback<T>(string input) {
        if (input is T output)
            return output;
        throw new Exception($"String cannot be converted to {nameof(T)}; add an explicit parseCallback");
    }
}
