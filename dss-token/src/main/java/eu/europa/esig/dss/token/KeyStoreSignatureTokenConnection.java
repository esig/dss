/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.token;

import eu.europa.esig.dss.model.DSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.DestroyFailedException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.Provider;

/**
 * Connection to a key store
 */
public class KeyStoreSignatureTokenConnection extends AbstractKeyStoreTokenConnection {

	private static final Logger LOG = LoggerFactory.getLogger(KeyStoreSignatureTokenConnection.class);

	/** The KeyStore */
	private final KeyStore keyStore;

	/** The password for the KeyStore */
	private final PasswordProtection password;

	/**
	 * Constructor from keyStore's binaries using a default provider.
	 *
	 * @param ksBytes byte array representing the keyStore
	 * @param ksType {@link String} type of the keyStore
	 * @param ksPassword {@link PasswordProtection}
	 */
	public KeyStoreSignatureTokenConnection(byte[] ksBytes, String ksType, PasswordProtection ksPassword) {
		this(ksBytes, ksType, ksPassword, null);
	}

	/**
	 * Constructor from keyStore's binaries using the custom {@code Provider}.
	 * When used, the {@code provider} will be added in java.security.Security.
	 *
	 * @param ksBytes
	 *            byte array representing the keyStore
	 * @param ksType
	 *            {@link String} type of the keyStore
	 * @param ksPassword
	 *            {@link PasswordProtection}
	 * @param provider
	 *            the security provider
	 */
	public KeyStoreSignatureTokenConnection(byte[] ksBytes, String ksType, PasswordProtection ksPassword, Provider provider) {
		this(new ByteArrayInputStream(ksBytes), ksType, ksPassword, provider);
	}

	/**
	 * Constructor with a path to KeyStore using a default provider.
	 *
	 * @param filepath
	 *            {@link String} path to the KeyStore
	 * @param ksType
	 *            {@link String} type of the keyStore
	 * @param ksPassword
	 *            {@link PasswordProtection}
	 * @throws IOException if an exception occurs
	 */
	public KeyStoreSignatureTokenConnection(String filepath, String ksType, PasswordProtection ksPassword) throws IOException {
		this(filepath, ksType, ksPassword, null);
	}

	/**
	 * Constructor with a path to KeyStore using the custom {@code Provider}.
	 * When used, the {@code provider} will be added in java.security.Security.
	 *
	 * @param filepath
	 *            {@link String} path to the KeyStore
	 * @param ksType
	 *            {@link String} type of the keyStore
	 * @param ksPassword
	 *            {@link PasswordProtection}
	 * @param provider
	 *            the security provider
	 * @throws IOException if an exception occurs
	 */
	public KeyStoreSignatureTokenConnection(String filepath, String ksType, PasswordProtection ksPassword, Provider provider) throws IOException {
		this(new File(filepath), ksType, ksPassword, provider);
	}

	/**
	 * Constructor from a file using a default provider.
	 *
	 * @param ksFile
	 *            {@link File} to the KeyStore
	 * @param ksType
	 *            {@link String} type of the keyStore
	 * @param ksPassword
	 *            {@link PasswordProtection}
	 * @throws IOException if an exception occurs
	 */
	public KeyStoreSignatureTokenConnection(File ksFile, String ksType, PasswordProtection ksPassword) throws IOException {
		this(ksFile, ksType, ksPassword, null);
	}

	/**
	 * Constructor from a file using the custom {@code Provider}.
	 * When used, the {@code provider} will be added in java.security.Security.
	 *
	 * @param ksFile
	 *            {@link File} to the KeyStore
	 * @param ksType
	 *            {@link String} type of the keyStore
	 * @param ksPassword
	 *            {@link PasswordProtection}
	 * @param provider
	 *            the security provider
	 * @throws IOException if an exception occurs
	 */
	public KeyStoreSignatureTokenConnection(File ksFile, String ksType, PasswordProtection ksPassword, Provider provider) throws IOException {
		this(Files.newInputStream(ksFile.toPath()), ksType, ksPassword, provider);
	}

	/**
	 * Construct a KeyStoreSignatureTokenConnection object using a default provider.
	 * Please note that the keystore password will also be used to retrieve the private key.
	 * For each keystore entry (identifiable by alias) the same private key password will be used.
	 * If you want to specify a separate private key password use the {@link #getKey(String, PasswordProtection)}
	 * method.
	 *
	 * @param ksStream
	 *            the inputstream which contains the keystore
	 * @param ksType
	 *            the keystore type
	 * @param password
	 *            the keystore password
	 */
	public KeyStoreSignatureTokenConnection(InputStream ksStream, String ksType, PasswordProtection password) {
		this(ksStream, ksType, password, null);
	}

	/**
	 * Construct a KeyStoreSignatureTokenConnection object using the custom {@code Provider}.
	 * Please note that the keystore password will also be used to retrieve the private key.
	 * For each keystore entry (identifiable by alias) the same private key password will be used.
	 * If you want to specify a separate private key password use the {@link #getKey(String, PasswordProtection)}
	 * method.
	 * When used, the {@code provider} will be added in java.security.Security.
	 * 
	 * @param ksStream
	 *            the inputstream which contains the keystore
	 * @param ksType
	 *            the keystore type
	 * @param password
	 *            the keystore password
	 * @param provider
	 *            the security provider
	 */
	public KeyStoreSignatureTokenConnection(InputStream ksStream, String ksType, PasswordProtection password, Provider provider) {
		super(provider);
		try (InputStream is = ksStream) {
			if (provider != null) {
				this.keyStore = KeyStore.getInstance(ksType, provider);
			} else {
				this.keyStore = KeyStore.getInstance(ksType);
			}
			this.password = password;
			this.keyStore.load(is, password.getPassword());
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to instantiate KeyStoreSignatureTokenConnection : %s", e.getMessage()), e);
		}
	}

	@Override
	protected KeyStore getKeyStore() {
		return keyStore;
	}

	@Override
	protected PasswordProtection getKeyProtectionParameter() {
		return password;
	}

	@Override
	public void close() {
		if (password != null) {
			try {
				password.destroy();
			} catch (DestroyFailedException e) {
				LOG.error("Unable to destroy password", e);
			}
		}
	}

}
