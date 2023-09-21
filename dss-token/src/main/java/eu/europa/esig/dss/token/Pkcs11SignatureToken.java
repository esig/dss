/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.token;

import eu.europa.esig.dss.model.DSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.UUID;

/**
 * PKCS11 token with callback
 */
public class Pkcs11SignatureToken extends AbstractKeyStoreTokenConnection {

	private static final Logger LOG = LoggerFactory.getLogger(Pkcs11SignatureToken.class);

	/** The type of the PKCS11 KeyStore */
	private static final String SUN_PKCS11_KEYSTORE_TYPE = "PKCS11";

	/** New line character (used for configuration building) */
	private static final String NEW_LINE = "\n";

	/** Double quote character (used for configuration building) */
	private static final String DOUBLE_QUOTE = "\"";

	/** The provider */
	private Provider provider;

	/** The path to the library */
	private final String pkcs11Path;

	/** The callback to enter a password/pincode */
	private final PasswordInputCallback callback;

	/** The slot Id to use */
	private final int slotId;

	/** The slot list index to use */
	private final int slotListIndex;

	/** Additional PKCS11 config */
	private final String extraPkcs11Config;

	/**
	 * Create the SignatureTokenConnection, using the provided path for the library.
	 *
	 * @param pkcs11Path
	 *            the path for the library (.dll, .so)
	 */
	public Pkcs11SignatureToken(String pkcs11Path) {
		this(pkcs11Path, (PasswordInputCallback) null);
	}

    /**
     * Create the SignatureTokenConnection, using the provided path for the library.
     *
     * @param pkcs11Path
     *            the path for the library (.dll, .so)
     * @param extraPkcs11Config
     *            extra configuration for pkcs11 library
     */
    public Pkcs11SignatureToken(String pkcs11Path, String extraPkcs11Config) {
        this(pkcs11Path, (PasswordInputCallback) null, extraPkcs11Config);
    }

	/**
	 * Sometimes, the password is known in advance. This create a SignatureTokenConnection and the keys will be accessed
	 * using the provided password. The default constructor for CallbackPkcs11SignatureToken.
	 *
	 * @param pkcs11Path
	 *            the path for the library (.dll, .so)
	 * @param password
	 *            the pin code / password to use
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordProtection password) {
		this(pkcs11Path, password, 0);
	}

    /**
     * Sometimes, the password is known in advance. This create a SignatureTokenConnection and the keys will be accessed
     * using the provided password. The default constructor for CallbackPkcs11SignatureToken.
     *
     * @param pkcs11Path
     *            the path for the library (.dll, .so)
     * @param password
     *            the pin code / password to use
     * @param extraPkcs11Config
     *            extra configuration for pkcs11 library
     */
    public Pkcs11SignatureToken(String pkcs11Path, PasswordProtection password, String extraPkcs11Config) {
        this(pkcs11Path, password, 0, extraPkcs11Config);
    }

	/**
	 * Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the password
	 * from the user. The default constructor for CallbackPkcs11SignatureToken.
	 *
	 * @param pkcs11Path
	 *            the path for the library (.dll, .so)
	 * @param callback
	 *            the callback to enter the pin code / password
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback) {
		this(pkcs11Path, callback, 0);
	}

    /**
     * Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the password
     * from the user. The default constructor for CallbackPkcs11SignatureToken.
     *
     * @param pkcs11Path
     *            the path for the library (.dll, .so)
     * @param callback
     *            the callback to enter the pin code / password
     * @param extraPkcs11Config
     *            extra configuration for pkcs11 library
     */
    public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback, String extraPkcs11Config) {
		this(pkcs11Path, callback, 0, -1, extraPkcs11Config);
    }

	/**
	 * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotIndex is used.
	 * This Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the
	 * password from the user.
	 *
	 * @param pkcs11Path
	 *            the path for the library (.dll, .so)
	 * @param password
	 *            the pin code / password to use
	 * @param slotId
	 *            the slotId to use
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordProtection password, int slotId) {
		this(pkcs11Path, new PrefilledPasswordCallback(password), slotId);
	}

    /**
     * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotIndex is used.
     * This Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the
     * password from the user.
     *
     * @param pkcs11Path
     *            the path for the library (.dll, .so)
     * @param password
     *            the pin code / password to use
     * @param slotId
     *            the slotId to use
     * @param extraPkcs11Config
     *            extra configuration for pkcs11 library
     */
    public Pkcs11SignatureToken(String pkcs11Path, PasswordProtection password, int slotId, String extraPkcs11Config) {
		this(pkcs11Path, new PrefilledPasswordCallback(password), slotId, -1, extraPkcs11Config);
    }

	/**
	 * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotIndex is used.
	 * This create a SignatureTokenConnection and the keys will be accessed using the provided password.
	 *
	 * @param pkcs11Path
	 *            the path for the library (.dll, .so)
	 * @param callback
	 *            the callback to enter the pin code / password
	 * @param slotId
	 *            the slotId to use
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback, int slotId) {
		this(pkcs11Path, callback, slotId, -1, null);
	}

	/**
	 * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotIndex is used. This
	 * create a SignatureTokenConnection and the keys will be accessed using the provided password.
	 *
	 * @param pkcs11Path
	 *                          the path for the library (.dll, .so)
	 * @param callback
	 *                          the callback to enter the pin code / password
	 * @param slotId
	 *                          the slotId to use
	 * @param extraPkcs11Config
	 *                          extra configuration for pkcs11 library
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback, int slotId, String extraPkcs11Config) {
		this(pkcs11Path, callback, slotId, -1, extraPkcs11Config);
	}

    /**
	 * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotListIndex is used.
	 * This create a SignatureTokenConnection and the keys will be accessed using the provided password.
	 *
	 * @param pkcs11Path
	 *                          the path for the library (.dll, .so)
	 * @param callback
	 *                          the callback to enter the pin code / password
	 * @param slotId
	 *                          the slotId to use (if negative, the parameter is not used)
	 * @param slotListIndex
	 *                          the slotListIndex to use (if negative, the parameter is not used)
	 * @param extraPkcs11Config
	 *                          extra configuration for pkcs11 library
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback, int slotId, int slotListIndex, String extraPkcs11Config) {
        this.pkcs11Path = pkcs11Path;
        this.callback = callback;
        this.slotId = slotId;
		this.slotListIndex = slotListIndex;
        this.extraPkcs11Config = extraPkcs11Config;
    }

	/**
	 * Gets the Provider to use
	 *
	 * @return {@link Provider}
	 */
	protected Provider getProvider() {
		if (provider == null) {
			String configString = buildConfig();
			LOG.debug("PKCS11 Config : \n{}", configString);

			provider = SunPKCS11Initializer.getProvider(configString);

			if (provider == null) {
				throw new DSSException("Unable to create PKCS11 provider");
			}

			// we need to add the provider to be able to sign later
			Security.addProvider(provider);
		}
		return provider;
	}

	/**
	 * Builds the PKCS11 config
	 *
	 * @return {@link String}
	 */
	protected String buildConfig() {
		/*
		 * The smartCardNameIndex int is added at the end of the smartCard name in order to enable the successive
		 * loading of multiple pkcs11 libraries
		 */
		String aPKCS11LibraryFileName = getPkcs11Path();
		aPKCS11LibraryFileName = escapePath(aPKCS11LibraryFileName);

		StringBuilder pkcs11Config = new StringBuilder();
		pkcs11Config.append("name = SmartCard").append(UUID.randomUUID());
		pkcs11Config.append(NEW_LINE).append("library = ").append(DOUBLE_QUOTE).append(aPKCS11LibraryFileName)
				.append(DOUBLE_QUOTE);

		if (slotId >= 0) {
			pkcs11Config.append(NEW_LINE).append("slot = ").append(slotId);
		}
		if (slotListIndex >= 0) {
			pkcs11Config.append(NEW_LINE).append("slotListIndex = ").append(slotListIndex);
		}

		if (extraPkcs11Config != null && !extraPkcs11Config.isEmpty()) {
			pkcs11Config.append(NEW_LINE).append(extraPkcs11Config);
		}

		return pkcs11Config.toString();
	}

	/**
	 * Replaces the path like ('\' to '\\')
	 *
	 * @param pathToEscape {@link String} to modify
	 * @return {@link String}
	 */
	protected String escapePath(String pathToEscape) {
		if (pathToEscape != null) {
			return pathToEscape.replace("\\", "\\\\");
		} else {
			return "";
		}
	}

	@Override
	protected KeyStore getKeyStore() throws DSSException {
		try {
			KeyStore keyStore = KeyStore.getInstance(SUN_PKCS11_KEYSTORE_TYPE, getProvider());
			keyStore.load(new KeyStore.LoadStoreParameter() {

				@Override
				public ProtectionParameter getProtectionParameter() {
					return new KeyStore.CallbackHandlerProtection(new CallbackHandler() {

						@Override
						public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
							for (Callback c : callbacks) {
								if (c instanceof PasswordCallback) {
									((PasswordCallback) c).setPassword(callback.getPassword());
									return;
								}
							}
							throw new DSSException("No password callback");
						}
					});
				}
			});
			return keyStore;
		} catch (Exception e) {
			if ("CKR_PIN_INCORRECT".equals(e.getMessage())) {
				throw new DSSException("Bad password for PKCS11", e);
			}
			throw new DSSException("Can't initialize Sun PKCS#11 security provider. Reason: " + e.getMessage(), e);
		}
	}

	/**
	 * Gets the path to PKCS library
	 *
	 * @return {@link String}
	 */
	protected String getPkcs11Path() {
		return pkcs11Path;
	}

	@Override
	protected PasswordProtection getKeyProtectionParameter() {
		return null;
	}

	@Override
	protected Signature getSignatureInstance(String javaSignatureAlgorithm) throws NoSuchAlgorithmException {
		return Signature.getInstance(javaSignatureAlgorithm, getProvider());
	}

	@Override
	public void close() {
		if (provider != null) {
			try {
				try {
					if (provider instanceof AuthProvider) {
						((AuthProvider) provider).logout();
					}
				} catch (LoginException e) {
					LOG.error("Unable to logout : {}", e.getMessage(), e);
				}
				provider.clear();
				Security.removeProvider(provider.getName());
			} catch (SecurityException e) {
				LOG.error("Unable to remove provider '{}'", provider.getName(), e);
			} finally {
				provider = null;
			}
		}
	}

}
