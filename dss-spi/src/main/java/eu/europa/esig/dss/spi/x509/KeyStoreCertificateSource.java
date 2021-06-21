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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

/**
 * Implements a CertificateSource using a KeyStore (PKCS12, JKS,...).
 * 
 * Note: PKCS12 + JDK7 don't allow trust store
 *
 */
@SuppressWarnings("serial")
public class KeyStoreCertificateSource extends CommonCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(KeyStoreCertificateSource.class);

	private KeyStore keyStore;
	private PasswordProtection passwordProtection;

	/**
	 * Constructor for KeyStoreCertificateSource.
	 * 
	 * This constructor allows to create a new empty keystore.
	 * 
	 * @param ksType     the keystore type
	 * @param ksPassword the keystore password
	 */
	public KeyStoreCertificateSource(final String ksType, final String ksPassword) {
		this((InputStream) null, ksType, ksPassword);
	}

	/**
	 * Constructor for KeyStoreCertificateSource.
	 * 
	 * @param ksFilePath the keystore filepath
	 * @param ksType     the keystore type
	 * @param ksPassword the keystore password
	 * @throws IOException if the file not exists
	 */
	public KeyStoreCertificateSource(final String ksFilePath, final String ksType, final String ksPassword) throws IOException {
		this(new File(ksFilePath), ksType, ksPassword);
	}

	/**
	 * Constructor for KeyStoreCertificateSource with <code>CertificatePool</code>.
	 * 
	 * @param ksFile
	 *            the keystore file
	 * @param ksType
	 *            the keystore type
	 * @param ksPassword
	 *            the keystore password
	 * @throws IOException
	 *             if the file not exists
	 */
	public KeyStoreCertificateSource(final File ksFile, final String ksType, final String ksPassword) throws IOException {
		this(new FileInputStream(ksFile), ksType, ksPassword);
	}

	/**
	 * The default constructor for KeyStoreCertificateSource.
	 *
	 * @param ksStream
	 *            the inputstream with the keystore (can be null to create a new keystore)
	 * @param ksType
	 *            the keystore type
	 * @param ksPassword
	 *            the keystore password
	 */
	public KeyStoreCertificateSource(final InputStream ksStream, final String ksType, final String ksPassword) {
		initKeystore(ksStream, ksType, ksPassword);
	}

	private void initKeystore(final InputStream ksStream, final String ksType, final String ksPassword) {
		try (InputStream is = ksStream) {
			keyStore = KeyStore.getInstance(ksType);
			final char[] password = (ksPassword == null) ? null : ksPassword.toCharArray();
			keyStore.load(is, password);
			passwordProtection = new PasswordProtection(password);
		} catch (GeneralSecurityException | IOException e) {
			throw new DSSException("Unable to initialize the keystore", e);
		}
	}

	/**
	 * This method allows to retrieve a certificate by its alias
	 * 
	 * @param alias
	 *            the certificate alias in the keystore
	 * @return the certificate
	 */
	public CertificateToken getCertificate(String alias) {
		try {
			String aliasToSearch = getKey(alias);
			if (keyStore.containsAlias(aliasToSearch)) {
				Certificate certificate = keyStore.getCertificate(aliasToSearch);
				return DSSUtils.loadCertificate(certificate.getEncoded());
			} else {
				LOG.warn("Certificate '{}' not found in the keystore", aliasToSearch);
				return null;
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to retrieve certificate from the keystore", e);
		}
	}

	/**
	 * This method returns all certificates from the keystore
	 */
	@Override
	public List<CertificateToken> getCertificates() {
		List<CertificateToken> list = new ArrayList<>();
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				Certificate certificate = keyStore.getCertificate(getKey(aliases.nextElement()));
				list.add(DSSUtils.loadCertificate(certificate.getEncoded()));
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to retrieve certificates from the keystore", e);
		}
		return Collections.unmodifiableList(list);
	}

	/**
	 * This method allows to add a list of certificates to the keystore
	 * 
	 * @param certificates
	 *            the list of certificates
	 */
	public void addAllCertificatesToKeyStore(List<CertificateToken> certificates) {
		for (CertificateToken certificateToken : certificates) {
			addCertificateToKeyStore(certificateToken);
		}
	}

	/**
	 * This method allows to add a certificate in the keystore. The generated alias will be the DSS ID.
	 * 
	 * @param certificateToken
	 *            the certificate to be added in the keystore
	 */
	public void addCertificateToKeyStore(CertificateToken certificateToken) {
		try {
			keyStore.setCertificateEntry(getKey(certificateToken.getDSSIdAsString()), certificateToken.getCertificate());
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to add certificate to the keystore", e);
		}
	}

	/**
	 * This method allows to remove a certificate from the keystore
	 * 
	 * @param alias
	 *            the certificate alias
	 */
	public void deleteCertificateFromKeyStore(String alias) {
		try {
			if (keyStore.containsAlias(alias)) {
				keyStore.deleteEntry(alias);
				LOG.info("Certificate '{}' successfuly removed from the keystore", alias);
			} else {
				LOG.warn("Certificate '{}' not found in the keystore", alias);
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to delete certificate from the keystore", e);
		}
	}

	/**
	 * This method allows to remove all certificates from the keystore
	 */
	public void clearAllCertificates() {
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				deleteCertificateFromKeyStore(alias);
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to clear certificates from the keystore", e);
		}
	}

	/**
	 * This method allows to store the keystore in the OutputStream
	 * 
	 * @param os
	 *            the OutputStream where to store the keystore
	 */
	public void store(OutputStream os) {
		try {
			keyStore.store(os, passwordProtection.getPassword());
		} catch (GeneralSecurityException | IOException e) {
			throw new DSSException("Unable to store the keystore", e);
		}
	}

	private String getKey(String inputKey) {
		if ("PKCS12".equals(keyStore.getType())) {
			// workaround for https://bugs.openjdk.java.net/browse/JDK-8079616:
			return inputKey.toLowerCase(Locale.ROOT);
		}
		return inputKey;
	}

}
