package eu.europa.esig.dss.token;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.Provider;

import eu.europa.esig.dss.model.DSSException;

public final class SunPKCS11Initializer {

	private static final String SUN_PKCS11_CLASSNAME = "sun.security.pkcs11.SunPKCS11";

	private SunPKCS11Initializer() {
	}

	public static Provider getProvider(String configString) {
		try (ByteArrayInputStream bais = new ByteArrayInputStream(configString.getBytes())) {
			Class<?> sunPkcs11ProviderClass = Class.forName(SUN_PKCS11_CLASSNAME);
			Constructor<?> constructor = sunPkcs11ProviderClass.getConstructor(InputStream.class);
			return (Provider) constructor.newInstance(bais);
		} catch (Exception e) {
			throw new DSSException("Unable to instantiate PKCS11 (JDK < 9) ", e);
		}
	}

}
