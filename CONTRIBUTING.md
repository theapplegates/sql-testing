Sequoia PGP is owned by the [p≡p foundation] and licensed under the
terms of the LGPLv2+.

  [p≡p foundation]: https://pep.foundation/

To finance its mission, privacy by default, the [p≡p foundation]
allows third parties to relicense its software.  Consistent with the
rules of a foundation, the money collected by the foundation in this
manner is fully reinvested in the foundation's mission, which includes
further development of Sequoia PGP.

To do this, the [p≡p foundation] needs permission from all
contributors to relicense their changes.  In return, the
[p≡p foundation] guarantees that *all* releases of Sequoia PGP (and
any other software it owns) will also be released under a GNU-approved
license.  That is, even if Foo Corp is granted a license to use
Sequoia PGP in a proprietary product, the exact code that Foo Corp
uses will also be licensed under a GNU-approved license.

If you want to contribute to Sequoia PGP, and you agree to the above,
please clear sign the [p≡p foundation]'s CLA (in [doc/CLA.txt]), and
send it to [contribution@pep.foundation] and cc
[team@sequoia-pgp.org].  Please use the same certificate as you'll use
to sign your commits.  This allows us to automatically link CLAs to
commits.

  [contribution@pep.foundation]: mailto:contribution@pep.foundation
  [team@sequoia-pgp.org]: mailto:team@sequoia-pgp.org
  [doc/CLA.txt]: https://gitlab.com/sequoia-pgp/sequoia/-/blob/main/doc/CLA.txt

You can do this using `sq` as follows:

```bash
$ sq sign --cleartext-signature doc/CLA.txt --signer-file contributor.pgp
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

p≡p Foundation – Contributor Copyright Assignment
...
```

Or using the
[chameleon](https://gitlab.com/sequoia-pgp/sequoia-chameleon-gnupg) as
follows:

```
$ gpg-sq -u FINGERPRINT --clear-sign doc/CLA.txt
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

p≡p Foundation – Contributor Copyright Assignment
...
```

Or, just use `gpg`, if `gpg-sq` or an API-compatible tool is installed
as `gpg` on your system.

This is an electronic assignment; no paper work is required.

Please direct questions regarding the CLA to
[contribution@pep.foundation] and cc [team@sequoia-pgp.org].

Thanks for considering contributing to Sequoia PGP!
