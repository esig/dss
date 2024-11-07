/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.suite.dss1794;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.SignatureCertificateSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS1794CrlTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/adbe_crl_signed.pdf"));
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<RelatedRevocationWrapper> revocationsByOrigin = signature.foundRevocations()
				.getRelatedRevocationsByOrigin(RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
		assertNotNull(revocationsByOrigin);
		assertEquals(1, revocationsByOrigin.size());
		assertEquals(RevocationType.CRL, revocationsByOrigin.get(0).getRevocationType());
		
		SignatureCertificateSource certificateSource = advancedSignatures.get(0).getCertificateSource();
		FoundCertificatesProxy foundCertificates = signature.foundCertificates();

		assertEquals(certificateSource.getSigningCertificateRefs().size(),
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size() +
				foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureById.isSigningCertificateIdentified());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<RelatedRevocationWrapper> adbeRevocationInfoArchivalRevocationData = signature.foundRevocations()
				.getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
		assertEquals(1, adbeRevocationInfoArchivalRevocationData.size());

		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			assertTrue(timestampWrapper.isSigningCertificateIdentified());
			assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
			assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
			
			CertificateRefWrapper signingCertificateReference = timestampWrapper.getSigningCertificateReference();
			assertNotNull(signingCertificateReference);
			assertTrue(signingCertificateReference.isDigestValuePresent());
			assertTrue(signingCertificateReference.isDigestValueMatch());
			assertTrue(signingCertificateReference.isIssuerSerialPresent());
			assertTrue(signingCertificateReference.isIssuerSerialMatch());

			boolean containsAdbeRevocation = false;
			List<RevocationWrapper> timestampedRevocations = timestampWrapper.getTimestampedRevocations();
			for (RevocationWrapper revocationWrapper : timestampedRevocations) {
				if (adbeRevocationInfoArchivalRevocationData.get(0).getId().equals(revocationWrapper.getId())) {
					containsAdbeRevocation = true;
				}
			}
			assertTrue(containsAdbeRevocation);
		}
	}

}
