﻿
using Example;
using SecureNet;

Console.WriteLine("A good signature is expected");

await ManifestSigning.Guard<Program>("Example.public-key.pgp", new FileInfo("manifest.txt.asc"), Verification.Verify);

Console.WriteLine("Good; a bad signature is expected");

await ManifestSigning.Guard("""
                             -----BEGIN PGP PUBLIC KEY BLOCK-----

                             mDMEZ9RAVxYJKwYBBAHaRw8BAQdAL50TjmI/V+43qtcgYRajZ9bwAE9QTr0bOId2
                             8P0xKcO0HUpvZXkgU21hbGVuIDxncGdAcXNtYWxseS5vcmc+iJMEExYKADsWIQRy
                             8DxyxDW4hMJyVPwOyzFWUNSo5AUCZ9RAVwIbAwULCQgHAgIiAgYVCgkICwIEFgID
                             AQIeBwIXgAAKCRAOyzFWUNSo5C6lAQCyMI5m0xfq43/hoYIv+x/8RpFLL3xQgpXn
                             TDKNKTEnXAD/f3NWPay9jR5ui3ztqGT+iBO4WFtd2qnOY3/1fdTphwu0HFFTbWFs
                             bHkgPGdpdGh1YkBxc21hbGx5Lm9yZz6IkwQTFgoAOxYhBHLwPHLENbiEwnJU/A7L
                             MVZQ1KjkBQJn1EVmAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEA7L
                             MVZQ1KjkAzwBAL9gVYsEkbUqMXAv7kCUYNCvUpJ6gojWS3sVQ57LyG4sAP0cWcQF
                             5doKXXaekYS2ci8myrAenDc2E96i0cZCjeVECbg4BGfUQFcSCisGAQQBl1UBBQEB
                             B0ANex60m0EF1IGW6vN+wJhRC41ErFtnnjLGUFVvvH+BBgMBCAeIeAQYFgoAIBYh
                             BHLwPHLENbiEwnJU/A7LMVZQ1KjkBQJn1EBXAhsMAAoJEA7LMVZQ1KjkcHoA/jxL
                             K5jKAtuTSjmiiOseHcVyYxblkRLB8FtNgHmGDpHwAQDS/+dV72JAULnhJCqb84Ih
                             WQhkp3LlWcxxbOTqTVMxAw==
                             =s7Eo
                             -----END PGP PUBLIC KEY BLOCK-----
                             """, new FileInfo("manifest.txt.asc.bad"), Verification.Verify);

Console.WriteLine("Bad; this should not happen");
