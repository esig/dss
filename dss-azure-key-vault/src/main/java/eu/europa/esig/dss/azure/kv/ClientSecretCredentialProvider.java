package eu.europa.esig.dss.azure.kv;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;

public class ClientSecretCredentialProvider implements AzureCredentialProvider {

    private final String tenantId;
    private final String clientId;
    private final String clientSecret;

    public ClientSecretCredentialProvider(String tenantId, String clientId, String clientSecret) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    @Override
    public TokenCredential getCredential() {
        return new ClientSecretCredentialBuilder()
            .tenantId(tenantId)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build();
    }
}
