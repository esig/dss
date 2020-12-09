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

import javax.security.auth.DestroyFailedException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;

/**
 * Connection to a key store
 */
public class KeyStoreSignatureTokenConnection extends AbstractKeyStoreTokenConnection {

	/** The KeyStore */
	private final KeyStore keyStore;

	/** The password for the KeyStore */
	private final PasswordProtection password;

	/**
	 * Constructor from keyStore's binaries
	 *
	 * @param ksBytes byte array representing the keyStore
	 * @param ksType {@link String} type of the keyStore
	 * @param ksPassword {@link PasswordProtection}
	 */
	public KeyStoreSignatureTokenConnection(byte[] ksBytes, String ksType, PasswordProtection ksPassword) {
		this(new ByteArrayInputStream(ksBytes), ksType, ksPassword);
	}

	/**
	 * Constructor with a path to KeyStore
	 *
	 * @param filepath {@link String} path to the KeyStore
	 * @param ksType {@link String} type of the keyStore
	 * @param ksPassword {@link PasswordProtection}
	 * @throws IOException if an exception occurs
	 */
	public KeyStoreSignatureTokenConnection(String filepath, String ksType, PasswordProtection ksPassword) throws IOException {
		this(new File(filepath), ksType, ksPassword);
	}

	/**
	 * Constructor from a file
	 *
	 * @param ksFile {@link File} to the KeyStore
	 * @param ksType {@link String} type of the keyStore
	 * @param ksPassword {@link PasswordProtection}
	 * @throws IOException if an exception occurs
	 */
	public KeyStoreSignatureTokenConnection(File ksFile, String ksType, PasswordProtection ksPassword) throws IOException {
		this(new FileInputStream(ksFile), ksType, ksPassword);
	}

	/**
	 * Construct a KeyStoreSignatureTokenConnection object.
	 * Please note that the keystore password will also be used to retrieve the private key.
	 * For each keystore entry (identifiable by alias) the same private key password will be used.
	 * 
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
		try (InputStream is = ksStream) {
			this.keyStore = KeyStore.getInstance(ksType);
			this.password = password;
			this.keyStore.load(is, password.getPassword());
		} catch (Exception e) {
			throw new DSSException("Unable to instantiate KeyStoreSignatureTokenConnection", e);
		}
	}

	@Override
	KeyStore getKeyStore() {
		return keyStore;
	}

	@Override
	PasswordProtection getKeyProtectionParameter() {
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
