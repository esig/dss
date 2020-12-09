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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Contains a validation data to be included into the signature
 */
public class ValidationDataForInclusion {

	/** Set of certificate tokens */
	private Set<CertificateToken> certificateTokens;

	/** List of CRL tokens */
	private List<CRLToken> crlTokens;

	/** List of OCSP tokens */
	private List<OCSPToken> ocspTokens;

	/**
	 * Sets certificate tokens ti be included into the signature
	 *
	 * @param certificateTokens a set of {@link CertificateToken}s
	 */
	void setCertificateTokens(Set<CertificateToken> certificateTokens) {
		this.certificateTokens = certificateTokens;
	}

	/**
	 * Sets CRL tokens ti be included into the signature
	 *
	 * @param crlTokens a list of {@link CRLToken}s
	 */
	void setCrlTokens(List<CRLToken> crlTokens) {
		this.crlTokens = crlTokens;
	}

	/**
	 * Sets OCSP tokens ti be included into the signature
	 *
	 * @param ocspTokens a list of {@link OCSPToken}s
	 */
	void setOcspTokens(List<OCSPToken> ocspTokens) {
		this.ocspTokens = ocspTokens;
	}

	/**
	 * Gets certificate tokens ti be included into the signature
	 *
	 * @return a set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getCertificateTokens() {
		if (Utils.isCollectionEmpty(certificateTokens)) {
			certificateTokens = new HashSet<>();
		}
		return certificateTokens;
	}

	/**
	 * Sets CRL tokens ti be included into the signature
	 *
	 * @return a list of {@link CRLToken}s
	 */
	public List<CRLToken> getCrlTokens() {
		if (Utils.isCollectionEmpty(crlTokens)) {
			crlTokens = new ArrayList<>();
		}
		return crlTokens;
	}

	/**
	 * Sets OCSP tokens ti be included into the signature
	 *
	 * @return a list of {@link OCSPToken}s
	 */
	public List<OCSPToken> getOcspTokens() {
		if (Utils.isCollectionEmpty(ocspTokens)) {
			ocspTokens = new ArrayList<>();
		}
		return ocspTokens;
	}

	/**
	 * Checks if the validation data is empty
	 *
	 * @return TRUE if the object is empty, FALSE otherwise
	 */
	public boolean isEmpty() {
		return Utils.isCollectionEmpty(certificateTokens) && Utils.isCollectionEmpty(crlTokens)
				&& Utils.isCollectionEmpty(ocspTokens);
	}

}
