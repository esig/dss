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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * This source of certificates handles any non trusted certificates. (ex: intermediate certificates used in building
 * certification chain)
 */
@SuppressWarnings("serial")
public class CommonCertificateSource implements CertificateSource {

	/**
	 * This variable represents the certificate pool with all encapsulated certificates
	 */
	private final CertificatePool certPool;

	/**
	 * The list of all encapsulated certificate tokens for the current source.
	 */
	private final List<CertificateToken> certificateTokens = new ArrayList<CertificateToken>();

	/**
	 * The default constructor to generate a certificates source with an independent certificates pool.
	 */
	public CommonCertificateSource() {
		// TODO useless ?
		certPool = new CertificatePool();
	}

	/**
	 * The default constructor with mandatory certificates pool.
	 *
	 * @param certPool
	 *            the certificate pool to use
	 */
	public CommonCertificateSource(final CertificatePool certPool) {
		Objects.requireNonNull(certPool, "Certificate pool is missing");
		this.certPool = certPool;
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.OTHER;
	}
	
	protected CertificatePool getCertificatePool() {
		return certPool;
	}

	/**
	 * This method adds an external certificate to the encapsulated pool and to the
	 * source. If the certificate is already present in the pool its source type is
	 * associated to the token.
	 *
	 * @param token
	 *              the certificate to add
	 * @return the corresponding certificate token
	 */
	@Override
	public CertificateToken addCertificate(final CertificateToken token) {
		final CertificateToken certToken = certPool.getInstance(token, getCertificateSourceType());
		if (!certificateTokens.contains(certToken)) {
			certificateTokens.add(certToken);
		}
		return certToken;
	}

	/**
	 * Retrieves the unmodifiable list of all certificate tokens from this source.
	 *
	 * @return all certificates from this source
	 */
	@Override
	public List<CertificateToken> getCertificates() {
		return Collections.unmodifiableList(certificateTokens);
	}

	/**
	 * This method is used internally to remove a certificate from the <code>CertificatePool</code>.
	 *
	 * @param certificate
	 *            the certificate to be removed
	 * @return true if removed
	 */
	public boolean removeCertificate(CertificateToken certificate) {
		return certificateTokens.remove(certificate);
	}

	/**
	 * This method returns the number of stored certificates in this source
	 * 
	 * @return number of certificates in this instance
	 */
	public int getNumberOfCertificates() {
		return certificateTokens.size();
	}
	
	/**
	 * Returns contained {@link CertificateToken} corresponding to the provided {@code digest}
	 * @param digest {@link Digest} to find the CertificateToken
	 * @return {@link CertificateToken}
	 */
	public CertificateToken getCertificateTokenByDigest(Digest digest) {
		for (CertificateToken certificate : certificateTokens) {
			byte[] digestValue = certificate.getDigest(digest.getAlgorithm());
			if (Arrays.equals(digestValue, digest.getValue())) {
				return certificate;
			}
		}
		return null;
	}

	@Override
	public boolean isTrusted(CertificateToken certificateToken) {
		return certPool.isTrusted(certificateToken);
	}

}
