package eu.europa.esig.dss.azure.kv;

import com.azure.core.credential.TokenCredential;

public interface AzureCredentialProvider {
    TokenCredential getCredential();
}
