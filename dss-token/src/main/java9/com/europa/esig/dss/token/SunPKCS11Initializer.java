package eu.europa.esig.dss.token;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;

import eu.europa.esig.dss.DSSException;

public final class SunPKCS11Initializer {

	private static final String SUN_PKCS11_PROVIDERNAME = "SunPKCS11";
	
	private SunPKCS11Initializer() {
		
	}

	public static Provider getProvider(String configString) {
		try {
			Provider provider = Security.getProvider(SUN_PKCS11_PROVIDERNAME);
			Method configureMethod = provider.getClass().getMethod("configure", String.class);
			// "--" is permitted in the constructor sun.security.pkcs11.Config
			return (Provider) configureMethod.invoke(provider, "--" + configString);
		} catch (Exception e) {
			throw new DSSException("Unable to instantiate PKCS11 (JDK >= 9)", e);
		}
	}

}
