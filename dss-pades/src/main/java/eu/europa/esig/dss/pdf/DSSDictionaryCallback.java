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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.validation.PAdESCRLSource;
import eu.europa.esig.dss.pades.validation.PAdESCertificateSource;
import eu.europa.esig.dss.pades.validation.PAdESOCSPSource;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Contains the DSS dictionary content
 */
public class DSSDictionaryCallback {

	/** The signature */
	private PAdESSignature signature;

	/** List of CRLs */
	private List<CRLToken> crls;

	/** List of OCSPs */
	private List<OCSPToken> ocsps;

	/** List of certificate tokens */
	private Set<CertificateToken> certificates;

	/**
	 * Gets the signature
	 *
	 * @return {@link PAdESSignature}
	 */
	public PAdESSignature getSignature() {
		return signature;
	}

	/**
	 * Sets the signature
	 *
	 * @param signature {@link PAdESSignature}
	 */
	public void setSignature(PAdESSignature signature) {
		this.signature = signature;
	}

	/**
	 * Gets the CRL tokens from a DSS dictionary
	 *
	 * @return a map between CRL objects ids and values
	 */
	public Map<Long, CRLBinary> getStoredCrls() {
		PAdESCRLSource crlSource = (PAdESCRLSource) signature.getCRLSource();
		return crlSource.getCrlMap();
	}

	/**
	 * Gets the OCSP tokens from a DSS dictionary
	 *
	 * @return a map between OCSP objects ids and values
	 */
	public Map<Long, BasicOCSPResp> getStoredOcspResps() {
		PAdESOCSPSource ocspSource = (PAdESOCSPSource) signature.getOCSPSource();
		return ocspSource.getOcspMap();
	}

	/**
	 * Gets the certificate tokens from a DSS dictionary
	 *
	 * @return a map between certificate objects ids and values
	 */
	public Map<Long, CertificateToken> getStoredCertificates() {
		PAdESCertificateSource certSource = (PAdESCertificateSource) signature.getCertificateSource();
		return certSource.getCertificateMap();
	}

	/**
	 * Gets the CRL tokens
	 *
	 * @return a list of {@link CRLToken}s
	 */
	public List<CRLToken> getCrls() {
		return crls;
	}

	/**
	 * Sets the CRL tokens
	 *
	 * @param crls a list of {@link CRLToken}s
	 */
	public void setCrls(List<CRLToken> crls) {
		this.crls = crls;
	}

	/**
	 * Gets the OCSP tokens
	 *
	 * @return a list of {@link OCSPToken}s
	 */
	public List<OCSPToken> getOcsps() {
		return ocsps;
	}

	/**
	 * Sets the OCSP tokens
	 *
	 * @param ocsps a list of {@link OCSPToken}s
	 */
	public void setOcsps(List<OCSPToken> ocsps) {
		this.ocsps = ocsps;
	}

	/**
	 * Gets the certificate tokens
	 *
	 * @return a list of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getCertificates() {
		return certificates;
	}

	/**
	 * Sets the certificate tokens
	 *
	 * @param certificates a list of {@link CertificateToken}s
	 */
	public void setCertificates(Set<CertificateToken> certificates) {
		this.certificates = certificates;
	}

}
