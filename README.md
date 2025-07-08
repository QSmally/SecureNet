
# SecureNet

A secure start-up guard for .NET Core.

## Description

This repository aims to (help) mitigate unauthorised runtime properties and vulnerabilities.

By embedding a PGP public key into the executable, and signing a manifest file with additional
information for further validation at runtime, it can be verified on start-up. The start-up
validation fails if the manifest or embedded public key is modified.

Once the manifest's signature is verified, implementation-specific validation using the manifest can
be done. For example, its contents could contain a hash of the executable assemblies. If an
unauthorsised DLL was added, the validation fails. The manifest could also contain secure
configuration options that can only be set by the deployer that signs the manifest.

## Implementation

It's recommended to use SecureNet as submodule, in order to skip NuGet downloads. But, do whatever
you want to do.

In order to provide the necessary credentials, an armoured (plain text) copy of your PGP public key
is needed. A clear-signed manifest (using the private key) is needed when packaging the executable.
For these examples, GnuPG (GPG) is used.

```bash
$ gpg --output public-key.pgp --armor --export <email>
$ gpg --clear-sign <manifest file>
```

It's intended to call `ManifestSigning.Guard` as the first subroutine in the application. The
following sections explain the different call variations.

```cs
using SecureNet;
```

### Embedded resource file

`Task ManifestSigning.Guard<T>(string publicKeyResource, FileInfo manifest, Func<string, bool>? manifestCallback = null);`

```cs
await ManifestSigning.Guard<Program>("RootNamespace.public-key.pgp", "manifest.asc");
```

`RootNamespace.csproj`:

```xml
<ItemGroup>
    <EmbeddedResource Include="public-key.pgp" />
</ItemGroup>
```

### Compile-time property

`Task ManifestSigning.Guard(string publicKey, FileInfo manifest, Func<string, bool>? manifestCallback = null);`

```cs
var publicKey = " ... "; // compile-time property or just pasted in
await ManifestSigning.Guard<Program>(publicKey, "manifest.asc");
```
