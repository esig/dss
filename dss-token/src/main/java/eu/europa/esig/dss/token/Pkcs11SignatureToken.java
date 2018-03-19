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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import eu.europa.esig.dss.DSSException;

/**
 * PKCS11 token with callback
 */
public class Pkcs11SignatureToken extends AbstractKeyStoreTokenConnection {

	private static final String NEW_LINE = "\n";

	private Provider provider;

	private final String _pkcs11Path;

	private final PasswordInputCallback callback;

	private final int slotId;

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
		this._pkcs11Path = pkcs11Path;
		this.callback = callback;
		this.slotId = slotId;
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
			pkcs11Config.append("name = SmartCard").append(UUID.randomUUID().toString()).append(NEW_LINE);
			pkcs11Config.append("library = \"").append(aPKCS11LibraryFileName).append("\"").append(NEW_LINE);
			pkcs11Config.append("slot = ").append(slotId);

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
				Security.removeProvider(provider.getName());
			} catch (SecurityException e) {
				LOG.error("Unable to remove provider '" + provider.getName() + "'", e);
			} finally {
				provider = null;
			}
		}
	}

}
