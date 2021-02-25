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

import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Class to build a ValidationDataForInclusion from a signature ValidationContext
 *
 */
public class ValidationDataForInclusionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationDataForInclusionBuilder.class);

	/** The ValidationContext to access and validation certificate chains */
	private final ValidationContext validationContext;

	/** The merged certificate source */
	private final ListCertificateSource completeCertificateSource;

	/** The certificate tokens to be excluded from the inclusion */
	private Collection<CertificateToken> excludeCertificateTokens;

	/** The CRL tokens to be excluded from the inclusion */
	private Collection<EncapsulatedRevocationTokenIdentifier<CRL>> excludeCRLs;

	/** The OCSP tokens to be excluded from the inclusion */
	private Collection<EncapsulatedRevocationTokenIdentifier<OCSP>> excludeOCSPs;
	
	/**
	 * The default constructor
	 * 
	 * @param validationContext a signature/timestamp {@link ValidationContext}
	 * @param completeCertificateSource {@link ListCertificateSource} containing all embedded certificates into signature and related timestamps
	 */
	public ValidationDataForInclusionBuilder(final ValidationContext validationContext, final ListCertificateSource completeCertificateSource) {
		this.validationContext = validationContext;
		this.completeCertificateSource = completeCertificateSource;
	}
	
	/**
	 * Sets a collection of certificate tokens to be excluded from the inclusion set
	 * 
	 * @param excludeCertificateTokens a collection of {@link CertificateToken}s to be excluded
	 * @return {@link ValidationDataForInclusionBuilder}
	 */
	public ValidationDataForInclusionBuilder excludeCertificateTokens(Collection<CertificateToken> excludeCertificateTokens) {
		this.excludeCertificateTokens = excludeCertificateTokens;
		return this;
	}

	/**
	 * Sets a collection of CRLs to be excluded from the inclusion list
	 * 
	 * @param excludeCRLs a collection of {@link EncapsulatedRevocationTokenIdentifier}s to be excluded from the inclusion list
	 * @return {@link ValidationDataForInclusionBuilder}
	 */
	public ValidationDataForInclusionBuilder excludeCRLs(Collection<EncapsulatedRevocationTokenIdentifier<CRL>> excludeCRLs) {
		this.excludeCRLs = excludeCRLs;
		return this;
	}

	/**
	 * Sets a collection of OCSPs to be excluded from the inclusion list
	 * 
	 * @param excludeOCSPs a collection of {@link EncapsulatedRevocationTokenIdentifier}s to be excluded from the inclusion list
	 * @return {@link ValidationDataForInclusionBuilder}
	 */
	public ValidationDataForInclusionBuilder excludeOCSPs(Collection<EncapsulatedRevocationTokenIdentifier<OCSP>> excludeOCSPs) {
		this.excludeOCSPs = excludeOCSPs;
		return this;
	}

	/**
	 * Creates a ValidationDataForInclusion for a signature/timestamp
	 * 
	 * @return {@link ValidationDataForInclusion}
	 */
	public ValidationDataForInclusion build() {
		ValidationDataForInclusion validationDataForInclusion = new ValidationDataForInclusion();
		Set<CertificateToken> validationCertificates = getValidationCertificates();
		validationDataForInclusion.setCrlTokens(getCRLsForInclusion(validationCertificates));
		validationDataForInclusion.setOcspTokens(getOCSPsForInclusion(validationCertificates));
		validationDataForInclusion.setCertificateTokens(getCertificatesForInclusion(validationCertificates));
		return validationDataForInclusion;
	}
	
	/**
	 * This method returns all certificates used during the validation process. If a certificate's public key is
	 * already present within the signature then it is ignored.
	 *
	 * @return set of certificates which public keys not yet present within the signature
	 */
	private Set<CertificateToken> getValidationCertificates() {
		Set<CertificateToken> certificatesForInclusion = completeCertificateSource.getAllCertificateTokens();
		// avoid adding of cross-certificates to the list
		final List<EntityIdentifier> publicKeys = getEntityIdentifierList(certificatesForInclusion);
		for (final CertificateToken certificateToken : validationContext.getProcessedCertificates()) {
			if (!publicKeys.contains(certificateToken.getEntityKey())) {
				certificatesForInclusion.add(certificateToken);
				publicKeys.add(certificateToken.getEntityKey());
			} else {
				LOG.debug("Certificate Token with Id : [{}] has not been added for inclusion. "
						+ "The same public key is already present!", certificateToken.getDSSIdAsString());
			}
		}
		return certificatesForInclusion;
	}

	private List<EntityIdentifier> getEntityIdentifierList(Collection<CertificateToken> certificateTokens) {
		final List<EntityIdentifier> entityIdentifiers = new ArrayList<>();
		for (CertificateToken certificateToken : certificateTokens) {
			entityIdentifiers.add(certificateToken.getEntityKey());
		}
		return entityIdentifiers;
	}
	
	/**
	 * Returns a list of certificates to be included into the signature
	 * 
	 * @param validationCertificates a set of {@link CertificateToken}s used during validation
	 * @return a set of {@link CertificateToken}s
	 */
	private Set<CertificateToken> getCertificatesForInclusion(Set<CertificateToken> validationCertificates) {
		if (Utils.isCollectionNotEmpty(excludeCertificateTokens)) {
			validationCertificates.removeAll(excludeCertificateTokens);
		}
		return validationCertificates;
	}

	/**
	 * This method returns CRLs that will be included in the LT profile.
	 *
	 * @param validationCertificates
	 *            {@link CertificateToken} contains all the certificate tokens used in the validation
	 * @return list of {@link CRLToken}s to be included to the signature
	 */
	private List<CRLToken> getCRLsForInclusion(final Set<CertificateToken> validationCertificates) {

		final List<CRLToken> crlTokens = new ArrayList<>();
		List<String> revocationIds = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(excludeCRLs)) {
			revocationIds = excludeCRLs.stream().map(r -> r.asXmlId()).collect(Collectors.toList());
		}

		for (final RevocationToken revocationToken : validationContext.getProcessedRevocations()) {
			if (revocationToken instanceof CRLToken && !revocationIds.contains(revocationToken.getDSSId().asXmlId()) 
					&& isAtLeastOneCertificateCovered(revocationToken, validationCertificates)) {
				final CRLToken crlToken = (CRLToken) revocationToken;
				revocationIds.add(crlToken.getDSSId().asXmlId());
				crlTokens.add(crlToken);
			}
		}
		return crlTokens;
	}

	/**
	 * This method returns OCSPs that will be included in the LT profile.
	 *
	 * @param validationCertificates
	 *            {@link CertificateToken} contains all the certificate tokens used in the validation
	 * @return list of {@link OCSPToken}s to be included to the signature
	 */
	private List<OCSPToken> getOCSPsForInclusion(final Set<CertificateToken> validationCertificates) {
		
		final List<OCSPToken> ocspTokens = new ArrayList<>();
		List<String> revocationIds = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(excludeOCSPs)) {
			revocationIds = excludeOCSPs.stream().map(r -> r.asXmlId()).collect(Collectors.toList());
		}
		
		for (final RevocationToken revocationToken : validationContext.getProcessedRevocations()) {
			if (revocationToken instanceof OCSPToken && !revocationIds.contains(revocationToken.getDSSId().asXmlId()) 
					&& isAtLeastOneCertificateCovered(revocationToken, validationCertificates)) {
				final OCSPToken ocspToken = (OCSPToken) revocationToken;
				revocationIds.add(ocspToken.getDSSId().asXmlId());
				ocspTokens.add(ocspToken);
			}
		}
		return ocspTokens;
	}
	
	/**
	 * The method allows to avoid adding of revocation data for certificates that had been removed from the inclusion
	 */
	private boolean isAtLeastOneCertificateCovered(RevocationToken revocationToken, final Collection<CertificateToken> certificateTokens) {
		String relatedCertificateID = revocationToken.getRelatedCertificateId();
		if (Utils.isStringNotEmpty(relatedCertificateID)) {
			for (CertificateToken certificateToken : certificateTokens) {
				if (certificateToken.getDSSIdAsString().equals(relatedCertificateID)) {
					return true;
				}
			}
		}
		return false;
	}

}
