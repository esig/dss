package eu.europa.esig.dss.azure.kv;

import java.nio.file.Path;
import java.nio.file.Paths;

public class ManagedIdentityBasedSigner {

    public static void main(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: java -jar managedidentity-signer.jar <vaultUrl> <keyId> <certName> <inputFile> [<outputFile>] [<clientId>]");
            System.err.println("Example: java -jar managedidentity-signer.jar https://myvault.vault.azure.net/ myKeyId myCert trustedlist.xml signed.xml");
            System.exit(1);
        }

        try {
            String vaultUrl = args[0];
            String keyId = args[1];
            String certName = args[2];
            Path inputPath = Paths.get(args[3]);
            Path outputPath = args.length >= 5 ? Paths.get(args[4]) : Paths.get("signed-" + inputPath.getFileName());
            String clientId = args.length >= 6 ? args[5] : null;

            AzureCredentialProvider provider =
                (clientId == null) ? new ManagedIdentityCredentialProvider() : new ManagedIdentityCredentialProvider(clientId);

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
