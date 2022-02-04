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

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;

import java.util.List;
import java.util.Set;

/**
 * The advanced signature contains a list of certificate that was needed to validate the signature. This class is a
 * basic skeleton that is able to retrieve the needed certificate from a list. The child need to retrieve the list of
 * wrapped certificates.
 *
 */
@SuppressWarnings("serial")
public abstract class SignatureCertificateSource extends TokenCertificateSource {

	/**
	 * The reference to the object containing all candidates to the signing
	 * certificate.
	 */
	protected CandidatesForSigningCertificate candidatesForSigningCertificate;

	/**
	 * Retrieves the list of all certificates present in a signed element (i.e. the CMS Signed data (CAdES))
	 *
	 * @return list of all certificates present in a signed element
	 */
	public List<CertificateToken> getSignedDataCertificates() {
		return getCertificateTokensByOrigin(CertificateOrigin.SIGNED_DATA);
	}

	/**
	 * Retrieves the list of all certificates present in the KeyInfo element (XAdES) (can be unsigned)
	 *
	 * @return list of all certificates present in KeyInfo
	 */
	public List<CertificateToken> getKeyInfoCertificates() {
		return getCertificateTokensByOrigin(CertificateOrigin.KEY_INFO);
	}

	/**
	 * Retrieves the list of all certificates from CertificateValues (XAdES/CAdES)
	 * 
	 * @return the list of all certificates present in the CertificateValues
	 */
	public List<CertificateToken> getCertificateValues() {
		return getCertificateTokensByOrigin(CertificateOrigin.CERTIFICATE_VALUES);
	}

	/**
	 * Retrieves the list of all certificates from the AttrAuthoritiesCertValues
	 * (XAdES)
	 * 
	 * @return the list of all certificates present in the AttrAuthoritiesCertValues
	 */
	public List<CertificateToken> getAttrAuthoritiesCertValues() {
		return getCertificateTokensByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES);
	}

	/**
	 * Retrieves the list of all certificates from the TimeStampValidationData
	 * (XAdES)
	 * 
	 * @return the list of all certificates present in the TimeStampValidationData
	 */
	public List<CertificateToken> getTimeStampValidationDataCertValues() {
		return getCertificateTokensByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
	}

	/**
	 * Retrieves the list of all certificates from the DSS dictionary (PAdES)
	 * 
	 * @return the list of all certificates present in the DSS dictionary
	 */
	public List<CertificateToken> getDSSDictionaryCertValues() {
		return getCertificateTokensByOrigin(CertificateOrigin.DSS_DICTIONARY);
	}

	/**
	 * Retrieves the list of all certificates from the VRI dictionary (PAdES)
	 * 
	 * @return the list of all certificates present in the VRI dictionary
	 */
	public List<CertificateToken> getVRIDictionaryCertValues() {
		return getCertificateTokensByOrigin(CertificateOrigin.VRI_DICTIONARY);
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s for the signing certificate
	 * (V1/V2)
	 * 
	 * @return the list of references to the signing certificate
	 */
	public List<CertificateRef> getSigningCertificateRefs() {
		return getCertificateRefsByOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s included in the attribute
	 * complete-certificate-references (CAdES) or the
	 * CompleteCertificateRefs/CompleteCertificateRefsV2 (XAdES)
	 * 
	 * @return the list of certificate references
	 */
	public List<CertificateRef> getCompleteCertificateRefs() {
		return getCertificateRefsByOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s included in the attribute
	 * attribute-certificate-references (CAdES) or the
	 * AttributeCertificateRefs/AttributeCertificateRefsV2 (XAdES)
	 * 
	 * @return the list of certificate references
	 */
	public List<CertificateRef> getAttributeCertificateRefs() {
		return getCertificateRefsByOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS);
	}

	/**
	 * Retrieves the Set of {@link CertificateToken}s for the signing certificate
	 * (V1/V2)
	 * 
	 * @return Set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getSigningCertificates() {
		return findTokensFromRefs(getSigningCertificateRefs());
	}
	
	/**
	 * Retrieves the Set of {@link CertificateToken}s according references to
	 * included in the attribute complete-certificate-references (CAdES) or the
	 * CompleteCertificateRefs/CompleteCertificateRefsV2 (XAdES)
	 * 
	 * @return Set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getCompleteCertificates() {
		return findTokensFromRefs(getCompleteCertificateRefs());
	}
	
	/**
	 * Retrieves the Set of {@link CertificateToken}s according to references
	 * included in the attribute attribute-certificate-references (CAdES) or the
	 * AttributeCertificateRefs/AttributeCertificateRefsV2 (XAdES)
	 * 
	 * @return Set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getAttributeCertificates() {
		return findTokensFromRefs(getAttributeCertificateRefs());
	}
	
	/**
	 * Gets an object containing the signing certificate or information indicating
	 * why it is impossible to extract it from the signature. If the signing
	 * certificate is identified then it is cached and the subsequent calls to this
	 * method will return this cached value. This method never returns null.
	 * 
	 * @param signingCertificateSource {@link CertificateSource} which allows to
	 *                                 resolve the signing certificate from external
	 *                                 sources
	 * @return {@link CandidatesForSigningCertificate}
	 */
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate(CertificateSource signingCertificateSource) {
		if (candidatesForSigningCertificate == null) {
			candidatesForSigningCertificate = extractCandidatesForSigningCertificate(signingCertificateSource);
		}
		return candidatesForSigningCertificate;
	}
	
	/**
	 * Extracts candidates to be a signing certificate from the source
	 * 
	 * @param signingCertificateSource {@link CertificateSource} which allows to resolve the signing certificate
	 *                                                           from external sources (optional)
	 * @return {@link CandidatesForSigningCertificate}
	 */
	protected abstract CandidatesForSigningCertificate extractCandidatesForSigningCertificate(
			CertificateSource signingCertificateSource);

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.SIGNATURE;
	}
	
}
