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
import java.security.KeyStore.ProtectionParameter;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
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

	private Provider _pkcs11Provider;

	private final String _pkcs11Path;

	private KeyStore _keyStore;

	private final PasswordInputCallback callback;

	private int slotIndex;

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
	 * Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the password
	 * from the user. The default constructor for CallbackPkcs11SignatureToken.
	 *
	 * @param pkcs11Path
	 *            the path for the library (.dll, .so)
	 * @param callback
	 *            the callback to enter the pin code / password
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback) {
		this._pkcs11Path = pkcs11Path;
		this.callback = callback;
		this.slotIndex = 0;
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
	public Pkcs11SignatureToken(String pkcs11Path, char[] password) {
		this(pkcs11Path, new PrefilledPasswordCallback(password));
	}

	/**
	 * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotIndex is used.
	 * This create a SignatureTokenConnection and the keys will be accessed using the provided password.
	 *
	 * @param pkcs11Path
	 *            the path for the library (.dll, .so)
	 * @param callback
	 *            the callback to enter the pin code / password
	 * @param slotIndex
	 *            the slotIndex to use
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback, int slotIndex) {
		this(pkcs11Path, callback);
		this.slotIndex = slotIndex;
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
	 * @param slotIndex
	 *            the slotIndex to use
	 */
	public Pkcs11SignatureToken(String pkcs11Path, char[] password, int slotIndex) {
		this(pkcs11Path, password);
		this.slotIndex = slotIndex;
	}

	private Provider getProvider() {
		try {
			if (_pkcs11Provider == null) {
				// check if the provider already exists
				final Provider[] providers = Security.getProviders();
				if (providers != null) {
					for (final Provider provider : providers) {
						final String providerInfo = provider.getInfo();
						if (providerInfo.contains(getPkcs11Path())) {
							_pkcs11Provider = provider;
							return provider;
						}
					}
				}
				// provider not already installed

				installProvider();
			}
			return _pkcs11Provider;
		} catch (ProviderException ex) {
			throw new DSSException("Not a PKCS#11 library", ex);
		}
	}

	@SuppressWarnings("restriction")
	private void installProvider() {

		/*
		 * The smartCardNameIndex int is added at the end of the smartCard name in order to enable the successive
		 * loading of multiple pkcs11 libraries
		 */
		String aPKCS11LibraryFileName = getPkcs11Path();
		aPKCS11LibraryFileName = escapePath(aPKCS11LibraryFileName);

		String pkcs11ConfigSettings = "name = SmartCard" + UUID.randomUUID().toString() + "\n" + "library = \"" + aPKCS11LibraryFileName
				+ "\"\nslotListIndex = " + slotIndex;

		byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
		ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

		sun.security.pkcs11.SunPKCS11 pkcs11 = new sun.security.pkcs11.SunPKCS11(confStream);
		_pkcs11Provider = pkcs11;

		Security.addProvider(_pkcs11Provider);
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

		if (_keyStore == null) {
			try {
				_keyStore = KeyStore.getInstance("PKCS11", getProvider());
				_keyStore.load(new KeyStore.LoadStoreParameter() {

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
			} catch (Exception e) {
				if (e instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
					if ("CKR_PIN_INCORRECT".equals(e.getMessage())) {
						throw new DSSException("Bad password for PKCS11", e);
					}
				}
				throw new DSSException("Can't initialize Sun PKCS#11 security provider. Reason: " + e.getMessage(), e);
			}
		}
		return _keyStore;
	}

	@Override
	ProtectionParameter getKeyProtectionParameter() {
		return null;
	}

	protected String getPkcs11Path() {
		return _pkcs11Path;
	}

	@Override
	public void close() {
		if (_pkcs11Provider != null) {
			try {
				Security.removeProvider(_pkcs11Provider.getName());
			} catch (Exception ex) {
				LOG.error(ex.getMessage(), ex);
			}
		}
		this._pkcs11Provider = null;
		this._keyStore = null;
	}

}
