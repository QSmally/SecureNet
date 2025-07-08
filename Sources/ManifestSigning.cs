
using PgpCore;

namespace SecureNet;

public static class ManifestSigning {

    public static async Task Guard<T>(
        string publicKeyResource,
        FileInfo manifest,
        Func<string, bool>? manifestCallback = null
    ) {
        var assembly = typeof(T).Assembly;
        var keyStream = assembly.GetManifestResourceStream(publicKeyResource);
        if (keyStream == null)
            throw new Exception($"Public key resource '{publicKeyResource}' could not be read from assembly.");
        using var publicKeyStream = new StreamReader(keyStream);
        var publicKey = publicKeyStream.ReadToEnd();

        using var inputFileStream = manifest.OpenRead();
        await Guard(publicKey, inputFileStream, manifestCallback);
    }

    public static async Task Guard(
        string publicKey,
        FileInfo manifest,
        Func<string, bool>? manifestCallback = null
    ) {
        using var inputFileStream = manifest.OpenRead();
        await Guard(publicKey, inputFileStream, manifestCallback);
    }

    public static async Task Guard(
        string publicKey,
        FileStream manifestStream,
        Func<string, bool>? manifestCallback = null
    ) {
        var encryptionKeys = new EncryptionKeys(publicKey);
        var pgp = new PGP(encryptionKeys);
        using var outputStream = new MemoryStream();

        var isGoodSignature = await pgp.VerifyClearAsync(manifestStream, outputStream);
        if (!isGoodSignature)
            throw new Exception("Signature is invalid guarded with the public key!");

        if (manifestCallback != null) {
            outputStream.Seek(0, SeekOrigin.Begin);
            using var outputStreamReader = new StreamReader(outputStream);
            var isGoodManifest = manifestCallback(outputStreamReader.ReadToEnd());
            if (!isGoodManifest)
                throw new Exception("Manifest verification failed!");
        }
    }
}
