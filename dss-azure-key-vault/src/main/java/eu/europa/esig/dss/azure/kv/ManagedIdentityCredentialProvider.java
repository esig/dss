package eu.europa.esig.dss.azure.kv;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ManagedIdentityCredential;
import com.azure.identity.ManagedIdentityCredentialBuilder;

public class ManagedIdentityCredentialProvider implements AzureCredentialProvider {

    private final String clientId; // optional, for user-assigned MI

    public ManagedIdentityCredentialProvider() {
        this.clientId = null;
    }

    public ManagedIdentityCredentialProvider(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public TokenCredential getCredential() {
        ManagedIdentityCredentialBuilder builder = new ManagedIdentityCredentialBuilder();
        if (clientId != null) {
            builder.clientId(clientId);
        }
        return builder.build();
    }
}
