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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateTokenRefMatcher;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import java.util.List;
import java.util.Objects;

/**
 * Represents a Source of certificates embedded into an OCSP Token
 *
 */
@SuppressWarnings("serial")
public class OCSPCertificateSource extends RevocationCertificateSource {
	
	/**
	 * The Basic OCSP Response
	 */
	private final BasicOCSPResp basicOCSPResp;

	/**
	 * The reference to the object containing all candidates to the signing
	 * certificate.
	 */
	private CandidatesForSigningCertificate candidatesForSigningCertificate;

	/**
	 * Default constructor
	 *
	 * @param basicOCSPResp {@link BasicOCSPResp}
	 */
	public OCSPCertificateSource(final BasicOCSPResp basicOCSPResp) {
		Objects.requireNonNull(basicOCSPResp, "BasicOCSPResp must be provided!");
		this.basicOCSPResp = basicOCSPResp;
		
		extractCertificateTokens();
		extractCertificatRefs();
	}
	
	private void extractCertificateTokens() {
		for (final X509CertificateHolder x509CertificateHolder : basicOCSPResp.getCerts()) {
			CertificateToken certificateToken = DSSASN1Utils.getCertificate(x509CertificateHolder);
			addCertificate(certificateToken, CertificateOrigin.BASIC_OCSP_RESP);
		}
	}

	private void extractCertificatRefs() {
		final ResponderId responderId = DSSRevocationUtils.getDSSResponderId(basicOCSPResp.getResponderId());
		CertificateRef signingCertificateRef = new CertificateRef();
		signingCertificateRef.setResponderId(responderId);
		signingCertificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		addCertificateRef(signingCertificateRef, CertificateRefOrigin.SIGNING_CERTIFICATE);
	}
	
	/**
	 * Returns candidates for the OCSP Response's signing certificate
	 * 
	 * @param certificateIssuer {@link CertificateToken} the issuer of a certificate covered by the OCSP
	 * @return {@link CandidatesForSigningCertificate}
	 */
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate(CertificateToken certificateIssuer) {
		if (candidatesForSigningCertificate == null) {
			candidatesForSigningCertificate = extractCandidatesForSigningCertificate(certificateIssuer);
		}
		return candidatesForSigningCertificate;
	}
	
	private CandidatesForSigningCertificate extractCandidatesForSigningCertificate(CertificateToken certificateIssuer) {
		CandidatesForSigningCertificate candidatesForSigningCertificate = new CandidatesForSigningCertificate();
		
		candidatesForSigningCertificate.add(new CertificateValidity(certificateIssuer));
		for (CertificateToken certificateToken : getCertificates()) {
			candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
		}
		
		List<CertificateRef> signingCertificateRefs = getCertificateRefsByOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		if (Utils.isCollectionNotEmpty(signingCertificateRefs)) {
			CertificateTokenRefMatcher matcher = new CertificateTokenRefMatcher();
			
			CertificateRef signingCertificateRef = signingCertificateRefs.iterator().next();
			for (CertificateValidity certificateValidity : candidatesForSigningCertificate.getCertificateValidityList()) {
				certificateValidity.setResponderIdPresent(signingCertificateRef.getResponderId() != null);

				CertificateToken certificateToken = certificateValidity.getCertificateToken();
				if (certificateToken != null) {
					certificateValidity.setResponderIdMatch(matcher.matchByResponderId(certificateToken, signingCertificateRef));
				}
			}
		}
		
		return candidatesForSigningCertificate;
	}
	
	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.OCSP_RESPONSE;
	}

}
