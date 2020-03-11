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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;

/**
 * The advanced signature contains a list of certificate that was needed to validate the signature. This class is a
 * basic skeleton that is able to retrieve the needed certificate from a list. The child need to retrieve the list of
 * wrapped certificates.
 *
 */
@SuppressWarnings("serial")
public abstract class SignatureCertificateSource extends TokenCertificateSource {
	
	/**
	 * Contains a list of all found {@link CertificateRef}s
	 */
	private List<CertificateRef> certificateRefs;

	/**
	 * The default constructor with mandatory certificates pool.
	 *
	 * @param certPool
	 *            the certificate pool
	 */
	protected SignatureCertificateSource(final CertificatePool certPool) {
		super(certPool);
	}
	/**
	 * Retrieves the list of all certificates present in a signed element (i.e. the CMS Signed data (CAdES))
	 *
	 * @return list of all certificates present in a signed element
	 */
	public abstract List<CertificateToken> getSignedDataCertificates();

	/**
	 * Retrieves the list of all certificates present in the KeyInfo element (XAdES) (can be unsigned)
	 *
	 * @return list of all certificates present in KeyInfo
	 */
	public abstract List<CertificateToken> getKeyInfoCertificates();

	/**
	 * Retrieves the list of all certificates from CertificateValues (XAdES/CAdES)
	 * 
	 * @return the list of all certificates present in the CertificateValues
	 */
	public abstract List<CertificateToken> getCertificateValues();

	/**
	 * Retrieves the list of all certificates from the AttrAuthoritiesCertValues
	 * (XAdES)
	 * 
	 * @return the list of all certificates present in the AttrAuthoritiesCertValues
	 */
	public abstract List<CertificateToken> getAttrAuthoritiesCertValues();

	/**
	 * Retrieves the list of all certificates from the TimeStampValidationData
	 * (XAdES)
	 * 
	 * @return the list of all certificates present in the TimeStampValidationData
	 */
	public abstract List<CertificateToken> getTimeStampValidationDataCertValues();

	/**
	 * Retrieves the list of all certificates from the DSS dictionary (PAdES)
	 * 
	 * @return the list of all certificates present in the DSS dictionary
	 */
	public List<CertificateToken> getDSSDictionaryCertValues() {
		return Collections.emptyList();
	}

	/**
	 * Retrieves the list of all certificates from the VRI dictionary (PAdES)
	 * 
	 * @return the list of all certificates present in the VRI dictionary
	 */
	public List<CertificateToken> getVRIDictionaryCertValues() {
		return Collections.emptyList();
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s for the signing certificate
	 * (V1/V2)
	 * 
	 * @return the list of references to the signing certificate
	 */
	public abstract List<CertificateRef> getSigningCertificateValues();
	
	/**
	 * Retrieves the list of {@link CertificateToken}s for the signing certificate (V1/V2)
	 * 
	 * @return list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getSigningCertificates() {
		return findTokensFromRefs(getSigningCertificateValues());
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s included in the attribute
	 * complete-certificate-references (CAdES) or the
	 * CompleteCertificateRefs/CompleteCertificateRefsV2 (XAdES)
	 * 
	 * @return the list of certificate references
	 */
	public abstract List<CertificateRef> getCompleteCertificateRefs();
	
	/**
	 * Retrieves the list of {@link CertificateToken}s according references to included in the attribute
	 * complete-certificate-references (CAdES) or the
	 * CompleteCertificateRefs/CompleteCertificateRefsV2 (XAdES)
	 * 
	 * @return list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getCompleteCertificates() {
		return findTokensFromRefs(getCompleteCertificateRefs());
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s included in the attribute
	 * attribute-certificate-references (CAdES) or the
	 * AttributeCertificateRefs/AttributeCertificateRefsV2 (XAdES)
	 * 
	 * @return the list of certificate references
	 */
	public abstract List<CertificateRef> getAttributeCertificateRefs();
	
	/**
	 * Retrieves the list of {@link CertificateToken}s according to references included in the attribute
	 * attribute-certificate-references (CAdES) or the
	 * AttributeCertificateRefs/AttributeCertificateRefsV2 (XAdES)
	 * 
	 * @return list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getAttributeCertificates() {
		return findTokensFromRefs(getAttributeCertificateRefs());
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.SIGNATURE;
	}
	
	@Override
	public List<CertificateRef> getAllCertificateRefs() {
		if (certificateRefs == null) {
			certificateRefs = new ArrayList<>();
			certificateRefs.addAll(getCompleteCertificateRefs());
			certificateRefs.addAll(getAttributeCertificateRefs());
			certificateRefs.addAll(getSigningCertificateValues());
		}
		return certificateRefs;
	}

}
