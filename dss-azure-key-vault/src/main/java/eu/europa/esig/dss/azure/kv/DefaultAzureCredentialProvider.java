package eu.europa.esig.dss.azure.kv;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;

public class DefaultAzureCredentialProvider implements AzureCredentialProvider {
    @Override
    public TokenCredential getCredential() {
        return new DefaultAzureCredentialBuilder().build();
    }
}
