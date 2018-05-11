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

import eu.europa.esig.dss.DSSException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.ByteArrayInputStream;
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

    private static final String NEW_LINE = "\n";
    private static final String DOUBLE_QUOTE = "\"";

    private Provider provider;

	private final String _pkcs11Path;

	private final PasswordInputCallback callback;

	private final int slotId;

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
        this(pkcs11Path, callback, 0, extraPkcs11Config);
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
        this(pkcs11Path, new PrefilledPasswordCallback(password), slotId, extraPkcs11Config);
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
		this(pkcs11Path, callback, slotId, null);
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
     * @param extraPkcs11Config
     *            extra configuration for pkcs11 library
     */
    public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback, int slotId, String extraPkcs11Config) {
        this._pkcs11Path = pkcs11Path;
        this.callback = callback;
        this.slotId = slotId;
        this.extraPkcs11Config = extraPkcs11Config;
    }

	@SuppressWarnings("restriction")
	protected Provider getProvider() {
		if (provider == null) {
			/*
			 * The smartCardNameIndex int is added at the end of the smartCard name in order to enable the successive
			 * loading of multiple pkcs11 libraries
			 */
			String aPKCS11LibraryFileName = getPkcs11Path();
			aPKCS11LibraryFileName = escapePath(aPKCS11LibraryFileName);

			StringBuilder pkcs11Config = new StringBuilder();
			pkcs11Config.append("name = SmartCard").append(UUID.randomUUID());
            pkcs11Config.append(NEW_LINE).append("library = ").append(DOUBLE_QUOTE).append(aPKCS11LibraryFileName).append(DOUBLE_QUOTE);
			pkcs11Config.append(NEW_LINE).append("slot = ").append(slotId);

			if(extraPkcs11Config != null && !extraPkcs11Config.isEmpty()) {
			    pkcs11Config.append(NEW_LINE).append(extraPkcs11Config);
            }

			String configString = pkcs11Config.toString();

			LOG.debug("PKCS11 Config : \n{}", configString);

			try (ByteArrayInputStream confStream = new ByteArrayInputStream(configString.getBytes())) {
				sun.security.pkcs11.SunPKCS11 sunPKCS11 = new sun.security.pkcs11.SunPKCS11(confStream);
				// we need to add the provider to be able to sign later
				Security.addProvider(sunPKCS11);
				provider = sunPKCS11;
				return provider;
			} catch (Exception e) {
				throw new DSSException("Unable to instantiate SunPKCS11", e);
			}
		}
		return provider;
	}

	private String escapePath(String pathToEscape) {
		if (pathToEscape != null) {
			return pathToEscape.replace("\\", "\\\\");
		} else {
			return "";
		}
	}

	@Override
	@SuppressWarnings("restriction")
	KeyStore getKeyStore() throws DSSException {
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS11", getProvider());
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
							throw new RuntimeException("No password callback");
						}
					});
				}
			});
			return keyStore;
		} catch (Exception e) {
			if (e instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
				if ("CKR_PIN_INCORRECT".equals(e.getMessage())) {
					throw new DSSException("Bad password for PKCS11", e);
				}
			}
			throw new DSSException("Can't initialize Sun PKCS#11 security provider. Reason: " + e.getMessage(), e);
		}
	}

	protected String getPkcs11Path() {
		return _pkcs11Path;
	}

	@Override
	PasswordProtection getKeyProtectionParameter() {
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
					if(provider instanceof AuthProvider) {
						((AuthProvider) provider).logout();
						provider.clear();
					}
				} catch (LoginException e) {
					LOG.error(e.getMessage(), e);
				}
				Security.removeProvider(provider.getName());
			} catch (SecurityException e) {
				LOG.error("Unable to remove provider '" + provider.getName() + "'", e);
			} finally {
				provider = null;
			}
		}
	}

}
