package eu.europa.esig.dss.azure.kv;

import java.nio.file.Path;
import java.nio.file.Paths;

public class ClientSecretCredentialBasedSigner {

    public static void main(String[] args) {
        if (args.length < 7) {
            System.err.println("Usage: java -jar clientsecret-signer.jar <vaultUrl> <keyId> <certName> <inputFile> <outputFile> <tenantId> <clientId> <clientSecret>");
            System.err.println("Example: java -jar clientsecret-signer.jar https://myvault.vault.azure.net/ myKeyId myCert trustedlist.xml signed.xml myTenantId myClientId myClientSecret");
            System.exit(1);
        }

        try {
            String vaultUrl = args[0];
            String keyId = args[1];
            String certName = args[2];
            Path inputPath = Paths.get(args[3]);
            Path outputPath = Paths.get(args[4]);
            String tenantId = args[5];
            String clientId = args[6];
            String clientSecret = args[7];

            AzureCredentialProvider provider = new ClientSecretCredentialProvider(tenantId, clientId, clientSecret);

            TlSigner signer = new TlSigner(vaultUrl, keyId, certName, provider);
            signer.signTrustedList(inputPath, outputPath);

            System.out.println("✅ Signing completed successfully. Output: " + outputPath.toAbsolutePath());
        } catch (Exception e) {
            System.err.println("❌ Signing failed: " + e.getMessage());
            System.err.println("Please check your arguments and try again.");
            System.exit(2);
        }
    }
}
