package eu.europa.esig.dss;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class DSSSecurityProvider {

	private static final Logger LOG = LoggerFactory.getLogger(DSSSecurityProvider.class);

	private DSSSecurityProvider() {
	}
	
	private static Provider securityProvider; 
	
	public static Provider getSecurityProvider() {
		if (securityProvider == null) {
			securityProvider = new BouncyCastleProvider();
			LOG.debug("DSSSecurityProvider initialized with {}", BouncyCastleProvider.class);
		}
		return securityProvider;
	}

	public static String getSecurityProviderName() {
		return getSecurityProvider().getName();
	}

	public static void setSecurityProvider(Provider provider) {
		LOG.debug("DSSSecurityProvider initialized with {}", provider.getClass());
		DSSSecurityProvider.securityProvider = provider;
	}

}
