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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESMultipleCertSourcesTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-X-CZ_SEF-5.xml");
	}
	
	@Override
	protected void checkCertificateChain(DiagnosticData diagnosticData) {
		super.checkCertificateChain(diagnosticData);
		
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		int certsFromTimestamp = 0;
		for (CertificateWrapper certificate : certificates) {
			List<CertificateSourceType> certSources = certificate.getSources();
			assertNotNull(certSources);
			assertNotEquals(0, certSources.size());
			if (certSources.contains(CertificateSourceType.TIMESTAMP)) {
				assertEquals(2, certSources.size());
				assertTrue(certSources.contains(CertificateSourceType.SIGNATURE));
				certsFromTimestamp++;
			}
			assertFalse(certificate.getSources().contains(CertificateSourceType.UNKNOWN));
			assertNotNull(certificate.getDigestAlgoAndValue());
			assertEquals(DigestAlgorithm.SHA256, certificate.getDigestAlgoAndValue().getDigestMethod());
		}
		assertEquals(1, certsFromTimestamp);
	}
	
	// DSS-2025
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		
		TimestampWrapper timestampWrapper = timestampList.get(0);
		assertTrue(timestampWrapper.isSigningCertificateIdentified());
		assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
		assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
		
		CertificateRefWrapper signingCertificateReference = timestampWrapper.getSigningCertificateReference();
		assertNotNull(signingCertificateReference);
		assertTrue(signingCertificateReference.isDigestValuePresent());
		assertTrue(signingCertificateReference.isDigestValueMatch());
		assertTrue(signingCertificateReference.isIssuerSerialPresent());
		assertTrue(signingCertificateReference.isIssuerSerialMatch());
		
		assertEquals(1, timestampWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
		List<OrphanCertificateWrapper> orphanSignCertRefs = timestampWrapper.foundCertificates()
				.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		assertEquals(1, orphanSignCertRefs.size());
		
		OrphanCertificateWrapper orphanCertificateWrapper = orphanSignCertRefs.get(0);
		assertEquals(1, orphanCertificateWrapper.getReferences().size());
		
		CertificateRefWrapper orphanSigningCertificateRefWrapper = orphanCertificateWrapper.getReferences().get(0);
		assertTrue(orphanSigningCertificateRefWrapper.isDigestValuePresent());
		assertFalse(orphanSigningCertificateRefWrapper.isDigestValueMatch());
		assertFalse(orphanSigningCertificateRefWrapper.isIssuerSerialPresent());
		assertFalse(orphanSigningCertificateRefWrapper.isIssuerSerialMatch());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		AdvancedSignature advancedSignature = advancedSignatures.get(0);
		SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(advancedSignature.getId());
		FoundCertificatesProxy foundCertificates = signature.foundCertificates();
		
		assertEquals(certificateSource.getSigningCertificateRefs().size(),
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size() +
				foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
		
		List<TimestampToken> allTimestamps = advancedSignature.getAllTimestamps();
		assertEquals(1, allTimestamps.size());
		TimestampToken timestampToken = allTimestamps.get(0);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		TimestampWrapper timestampWrapper = timestampList.get(0);

		certificateSource = timestampToken.getCertificateSource();
		foundCertificates = timestampWrapper.foundCertificates();
		assertEquals(certificateSource.getSigningCertificateRefs().size(),
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size() +
				foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}

}
