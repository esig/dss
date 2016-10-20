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
package eu.europa.esig.dss.x509;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * Implements a CertificateSource using a JKS KeyStore.
 *
 */
public class KeyStoreCertificateSource extends CommonCertificateSource {

	private static final Logger logger = LoggerFactory.getLogger(KeyStoreCertificateSource.class);

	private static final String DEFAULT_KEYSTORE_TYPE = "JKS";

	private File keyStoreFile;

	private String password;

	private String keyStoreType;

	/**
	 * The default constructor for KeyStoreCertificateSource.
	 *
	 * @param keyStoreFilename
	 * @param password
	 * @param certPool
	 */
	public KeyStoreCertificateSource(final String keyStoreFilename, final String password, final CertificatePool certPool) {
		this(new File(keyStoreFilename), DEFAULT_KEYSTORE_TYPE, password, certPool);
	}

	/**
	 * The default constructor for KeyStoreCertificateSource.
	 *
	 * @param keyStoreFile
	 * @param password
	 * @param certPool
	 */
	public KeyStoreCertificateSource(final File keyStoreFile, final String password, final CertificatePool certPool) {
		this(keyStoreFile, DEFAULT_KEYSTORE_TYPE, password, certPool);
	}

	/**
	 * The default constructor for KeyStoreCertificateSource without <code>CertificatePool</code>.
	 *
	 * @param keyStoreFilename
	 * @param password
	 */
	public KeyStoreCertificateSource(final String keyStoreFilename, final String password) {
		this(new File(keyStoreFilename), DEFAULT_KEYSTORE_TYPE, password);
	}

	/**
	 * The default constructor for KeyStoreCertificateSource without <code>CertificatePool</code>.
	 *
	 * @param keyStoreFile
	 * @param password
	 */
	public KeyStoreCertificateSource(final File keyStoreFile, final String password) {
		this(keyStoreFile, DEFAULT_KEYSTORE_TYPE, password);
	}

	/**
	 * The default constructor for KeyStoreCertificateSource.
	 *
	 * @param keyStoreFile
	 * @param keyStoreType
	 * @param password
	 * @param certPool
	 */
	public KeyStoreCertificateSource(final File keyStoreFile, final String keyStoreType, final String password, final CertificatePool certPool) {
		super(certPool);
		this.keyStoreFile = keyStoreFile;
		this.keyStoreType = keyStoreType;
		this.password = password;
	}

	/**
	 * The default constructor for KeyStoreCertificateSource without <code>CertificatePool</code>.
	 *
	 * @param keyStoreFile
	 * @param keyStoreType
	 * @param password
	 */
	public KeyStoreCertificateSource(final File keyStoreFile, final String keyStoreType, final String password) {
		super();
		this.keyStoreFile = keyStoreFile;
		this.keyStoreType = keyStoreType;
		this.password = password;
	}

	public void addCertificateToKeyStore(CertificateToken certificateToken) {
		try {
			KeyStore keyStore = getKeyStore();
			keyStore.setCertificateEntry(certificateToken.getDSSIdAsString(), certificateToken.getCertificate());
			persistKeyStore(keyStore);
		} catch (Exception e) {
			throw new DSSException("Unable to add certificate to the keystore", e);
		}
	}

	private void persistKeyStore(KeyStore keyStore) {
		OutputStream os = null;
		try {
			os = new FileOutputStream(keyStoreFile);
			keyStore.store(os, password.toCharArray());
		} catch (Exception e) {
			throw new DSSException("Unable to persist the keystore", e);
		} finally {
			Utils.closeQuietly(os);
		}
	}

	public CertificateToken getCertificate(String dssId) {
		try {
			KeyStore keyStore = getKeyStore();
			if (keyStore.containsAlias(dssId)) {
				Certificate certificate = keyStore.getCertificate(dssId);
				return DSSUtils.loadCertificate(certificate.getEncoded());
			} else {
				logger.warn("Certificate " + dssId + " not found in the keystore");
				return null;
			}
		} catch (Exception e) {
			throw new DSSException("Unable to retrieve certificate from the keystore", e);
		}
	}

	public void deleteCertificateFromKeyStore(String dssId) {
		try {
			KeyStore keyStore = getKeyStore();
			if (keyStore.containsAlias(dssId)) {
				keyStore.deleteEntry(dssId);
				persistKeyStore(keyStore);
				logger.info("Certificate with ID " + dssId + " successfuly removed from the keystore");
			} else {
				logger.warn("Certificate " + dssId + " not found in the keystore");
			}
		} catch (Exception e) {
			throw new DSSException("Unable to delete certificate from the keystore", e);
		}
	}

	public List<CertificateToken> getCertificatesFromKeyStore() {
		List<CertificateToken> list = new ArrayList<CertificateToken>();
		try {
			KeyStore keyStore = getKeyStore();
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (keyStore.isCertificateEntry(alias)) {
					Certificate certificate = keyStore.getCertificate(alias);
					CertificateToken certificateToken = DSSUtils.loadCertificate(certificate.getEncoded());
					list.add(certificateToken);
				}
			}
		} catch (Exception e) {
			throw new DSSException("Unable to retrieve certificates from the keystore", e);
		}
		return list;
	}

	@Override
	public List<CertificateToken> getCertificates() {
		return Collections.unmodifiableList(getCertificatesFromKeyStore());
	}

	private KeyStore getKeyStore() throws KeyStoreException, IOException, GeneralSecurityException {
		KeyStore store = null;
		InputStream is = null;
		try {
			store = KeyStore.getInstance(keyStoreType);
			is = new FileInputStream(keyStoreFile);
			store.load(is, password.toCharArray());
		} finally {
			Utils.closeQuietly(is);
		}
		return store;
	}

}
