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
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSEncodingException;
import eu.europa.esig.dss.DSSEncodingException.MSG;
import eu.europa.esig.dss.DSSUtils;

/**
 * Implements a CertificateSource using a JKS KeyStore.
 *
 *
 */

public class KeyStoreCertificateSource extends CommonCertificateSource {

	private static final Logger logger = LoggerFactory.getLogger(KeyStoreCertificateSource.class);

	private static final String DEFAULT_KEYSTORE_TYPE = "JKS";

	private static final Logger LOG = LoggerFactory.getLogger(KeyStoreCertificateSource.class);

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

	public List<CertificateToken> populate() {
		List<CertificateToken> list = new ArrayList<CertificateToken>();
		try {
			KeyStore keyStore = getKeyStore();
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				final Certificate certificate = keyStore.getCertificate(alias);
				if (certificate != null) {
					X509Certificate x509Certificate = (X509Certificate) certificate;
					LOG.debug("Alias " + alias + " Cert " + x509Certificate.getSubjectDN());

					CertificateToken certToken = certPool.getInstance(new CertificateToken(x509Certificate), CertificateSourceType.OTHER);
					list.add(certToken);
				}
				Certificate[] certificateChain = keyStore.getCertificateChain(alias);
				if (certificateChain != null) {
					for (Certificate chainCert : certificateChain) {
						LOG.debug("Alias " + alias + " Cert " + ((X509Certificate) chainCert).getSubjectDN());
						CertificateToken certToken = certPool.getInstance(new CertificateToken((X509Certificate) chainCert), CertificateSourceType.OCSP_RESPONSE);
						if (!list.contains(certToken)) {
							list.add(certToken);
						}
					}
				}
			}
		} catch (Exception e) {
			throw new DSSEncodingException(MSG.CERTIFICATE_CANNOT_BE_READ, e);
		}
		return list;
	}

	public void addCertificateToKeyStore(CertificateToken certificateToken) {
		try {
			KeyStore keyStore = getKeyStore();
			keyStore.setCertificateEntry(certificateToken.getDSSIdAsString(), certificateToken.getCertificate());
			persistKeyStore(keyStore);
		} catch (Exception e) {
			logger.error("Unable to add certificate to the keystore : " + e.getMessage(), e);
		}
	}

	private void persistKeyStore(KeyStore keyStore) {
		OutputStream os = null;
		try {
			os = new FileOutputStream(keyStoreFile);
			keyStore.store(os, password.toCharArray());
		} catch (Exception e) {
			logger.error("Unable to persist the keystore : " + e.getMessage(), e);
		} finally {
			IOUtils.closeQuietly(os);
		}
	}

	public void deleteCertificateFromKeyStore(String dssId) {
		KeyStore keyStore = getKeyStore();
		try {
			if (keyStore.containsAlias(dssId)) {
				keyStore.deleteEntry(dssId);
				persistKeyStore(keyStore);
				logger.info("Certificate with ID " + dssId + " successfuly removed from the keystore");
			} else {
				logger.warn("Certificate " + dssId + " not found in the keystore");
			}
		} catch (Exception e) {
			logger.error("Unable to delete certificate from the keystore : " + e.getMessage(), e);
		}
	}

	public List<CertificateToken> getCertificatesFromKeyStore() {
		List<CertificateToken> list = new ArrayList<CertificateToken>();

		KeyStore keyStore = getKeyStore();
		try {
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
			logger.error("Unable to retrieve certificates from the keystore : " + e.getMessage(), e);
		}
		return list;
	}

	private KeyStore getKeyStore() {
		KeyStore store = null;
		InputStream is = null;
		try {
			store = KeyStore.getInstance(keyStoreType);
			is = new FileInputStream(keyStoreFile);
			store.load(is, password.toCharArray());
		} catch (Exception e) {
			logger.error("Unable to read keystore : " + e.getMessage(), e);
		} finally {
			IOUtils.closeQuietly(is);
		}
		return store;
	}
}
