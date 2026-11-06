# Trust the Workglen local Admin certificate on macOS

Workglen Admin listens only on the local machine at `https://localhost:8443` by default. Public certificate authorities do not issue certificates for `localhost`, so macOS must explicitly trust the public Workglen Local Admin CA once.

## Guided click path

1. In Finder, open `~/Library/Application Support/Workglen`.
2. Double-click `install-local-ca.command`.
3. The helper opens only `etc/local-ca.cer`, the public CA certificate, in Keychain Access. It never installs a private key and never changes trust automatically.
4. Add the certificate to the **Login** keychain for the current user. Choose **System** instead if every user on the Mac needs the trust; macOS will require administrator approval.
5. In Keychain Access, find and double-click **Workglen Local Admin CA**.
6. Expand **Trust**, set **When using this certificate** to **Always Trust**, then close the window and approve the macOS prompt.
7. Quit and reopen Safari and Chrome. Return to the helper and press Return to open the Admin console.

If macOS does not open the certificate automatically, open Keychain Access, select the intended keychain, choose **File > Import Items**, and select:

```text
~/Library/Application Support/Workglen/etc/local-ca.cer
```

Then complete steps 5 through 7 above. Corporate-managed Macs may require the organization's approved certificate-trust process.

## Verify and troubleshoot

- Open `https://localhost:8443/mail-security` using the port selected during installation.
- In Chrome, review local certificates under **Settings > Privacy and security > Security > Manage certificates**. On macOS this leads to the certificate management backed by Keychain Access.
- Confirm the certificate is named **Workglen Local Admin CA**. Its critical constraints permit only exact `localhost`, `127.0.0.1`, and `::1` names.
- Never import or share `local-key.pem`. It is the localhost server's private key.
- There is no CA private-key file. Workglen discards the CA signing key immediately after issuing the local certificate.

The local leaf and CA expire together within one year. Follow the renewal procedure in [MAC-ADMIN-LIGHTSAIL.md](MAC-ADMIN-LIGHTSAIL.md) before expiry, then remove the old trusted CA after verifying the replacement in Safari and Chrome.
