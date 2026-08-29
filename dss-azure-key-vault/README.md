# DSS Azure Key Vault Based Token

This module provides Azure Key Vault based signing support for DSS signing, including two runnable shaded JARs:

- `managed-identity-signer.jar` signing using managed identity authentication and signing 
- `client-secret-signer.jar` for signing using client secret authentication

## Maven dependency

Add this module as a dependency in your Maven project:

```xml
<dependency>
  <groupId>eu.europa.ec.joinup.sd-dss</groupId>
  <artifactId>dss-azure-key-vault</artifactId>
  <version>6.4</version>
</dependency>
```

The `groupId` and `version` are inherited from the parent `sd-dss` project.

## Build

From the module folder:

```bash
mvn clean package
```

Or from the root of the multi-module repository:

```bash
mvn -pl dss-azure-key-vault -am clean package
```

After a successful build, the shaded executable JARs are available in `target/`.

## Shaded JARs

The module produces two shaded JARs:

- `target/dss-azure-key-vault-6.4-managed-identity-signer.jar`
- `target/dss-azure-key-vault-6.4-client-secret-signer.jar`

Each JAR contains all required dependencies and a `Main-Class` entrypoint.

## Run the shaded JARs

### Managed Identity

```bash
java -jar target/dss-azure-key-vault-6.4-managed-identity-signer.jar \
  https://<your-vault-name>.vault.azure.net/ \
  <keyId> \
  <certName> \
  <inputFile> \
  [<outputFile>] \
  [<clientId>]
```

Example:

```bash
java -jar target/dss-azure-key-vault-6.4-managed-identity-signer.jar \
  https://myvault.vault.azure.net/ \
  myKeyId \
  myCert \
  trustedlist.xml \
  signed.xml
```

If you need to target a specific user-assigned managed identity, pass `<clientId>` as the sixth argument.

### Client Secret

```bash
java -jar target/dss-azure-key-vault-6.4-client-secret-signer.jar \
  https://<your-vault-name>.vault.azure.net/ \
  <keyId> \
  <certName> \
  <inputFile> \
  <outputFile> \
  <tenantId> \
  <clientId> \
  <clientSecret>
```

Example:

```bash
java -jar target/dss-azure-key-vault-6.4-client-secret-signer.jar\
  https://myvault.vault.azure.net/ \
  myKeyId \
  myCert \
  trustedlist.xml \
  signed.xml \
  myTenantId \
  myClientId \
  myClientSecret
```

## Library usage

If you use this module as a dependency, the main signing entrypoints are:

- `eu.europa.esig.dss.azure.kv.ManagedIdentityCredentialProvider`
- `eu.europa.esig.dss.azure.kv.ClientSecretCredentialProvider`
- `eu.europa.esig.dss.azure.kv.TlSigner`

Example:

```java
Path inputPath = Paths.get("trustedlist.xml");
Path outputPath = Paths.get("signed.xml");

AzureCredentialProvider provider = new ManagedIdentityCredentialProvider();
// or for client secret authentication:
// AzureCredentialProvider provider = new ClientSecretCredentialProvider(tenantId, clientId, clientSecret);

TlSigner signer = new TlSigner(vaultUrl, keyId, certName, provider);
signer.signTrustedList(inputPath, outputPath);
```

## Azure Key Vault prerequisites

- The Key Vault must contain the target key and certificate referenced by `keyId` and `certName`.
- The identity used for signing must have Key Vault access to read keys and certificates.
- For managed identity:
  - assign the managed identity access to the Key Vault, either via an access policy or Azure RBAC role such as `Key Vault Crypto Service Encryption User` / `Key Vault Certificates Officer`.
  - if using a user-assigned managed identity, obtain the client ID from Azure and pass it as the optional sixth argument to `dss-azure-key-vault-6.4-managed-identity-signer.jar`.

    Example Azure CLI command:

    ```bash
    az identity show --name <user-assigned-identity-name> --resource-group <resource-group> --query clientId -o tsv
    ```

    Then run:

    ```bash
    java -jar target/dss-azure-key-vault-6.4-managed-identity-signer.jar \
      https://<your-vault-name>.vault.azure.net/ \
      <keyId> \
      <certName> \
      <inputFile> \
      [<outputFile>] \
      <clientId>
    ```
- For client secret authentication:
  - create a service principal in Azure AD, grant it Key Vault key and certificate permissions, and pass `tenantId`, `clientId`, and `clientSecret` to `dss-azure-key-vault-6.4-client-secret-signer.jar`.

## Notes

- `managed-identity-signer.jar` is intended for Azure managed identity scenarios.(Recommended)
- `client-secret-signer.jar` is intended for service principal authentication with a client secret.
