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

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper of a PrivateKeyEntry coming from a KeyStore.
 *
 */
public class KSPrivateKeyEntry implements DSSPrivateKeyAccessEntry {

	/** The key's alias */
	private final String alias;

	/** The certificate */
	private final CertificateToken certificate;

	/** The corresponding certificate chain */
	private final CertificateToken[] certificateChain;

	/** The private key */
	private final PrivateKey privateKey;

	/**
	 * The default constructor for KSPrivateKeyEntry.
	 * 
	 * @param alias
	 *            the given alias
	 * @param privateKeyEntry
	 *            the keystore private key entry
	 */
	public KSPrivateKeyEntry(final String alias, final PrivateKeyEntry privateKeyEntry) {
		this.alias = alias;
		certificate = new CertificateToken((X509Certificate) privateKeyEntry.getCertificate());
		final List<CertificateToken> x509CertificateList = new ArrayList<>();
		final Certificate[] simpleCertificateChain = privateKeyEntry.getCertificateChain();
		for (final Certificate currentCertificate : simpleCertificateChain) {
			x509CertificateList.add(new CertificateToken((X509Certificate) currentCertificate));
		}
		final CertificateToken[] certificateChainArray = new CertificateToken[x509CertificateList.size()];
		certificateChain = x509CertificateList.toArray(certificateChainArray);
		privateKey = privateKeyEntry.getPrivateKey();
	}

	/**
	 * Get the entry alias
	 * 
	 * @return the alias
	 */
	public String getAlias() {
		return alias;
	}

	@Override
	public CertificateToken getCertificate() {
		return certificate;
	}

	@Override
	public CertificateToken[] getCertificateChain() {
		return certificateChain;
	}

	@Override
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return EncryptionAlgorithm.forKey(certificate.getPublicKey());
	}

}
