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
package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class ASN1PolicyTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/AD-RB.pdf"));
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<>();
		signaturePoliciesByUrl.put("http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_0.der",
				new InMemoryDocument(getClass().getResourceAsStream("/validation/PA_PAdES_AD_RB_v1_0.der")));
		signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		return validator;
	}
	
	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);
		
		SignatureWrapper firstSignature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(firstSignature.isBLevelTechnicallyValid());

		assertTrue(firstSignature.isPolicyPresent());
		assertTrue(firstSignature.isPolicyAsn1Processable());
		assertTrue(firstSignature.isPolicyIdentified());
		assertTrue(firstSignature.isPolicyDigestValid());
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);
		
		assertEquals(2, diagnosticData.getSignatureIdList().size());
	}
	
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
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		SignatureCertificateSource certificateSource = advancedSignatures.get(0).getCertificateSource();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();

		assertEquals(certificateSource.getSigningCertificateRefs().size(),
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size() +
				foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper firstSignature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(firstSignature.isSigningCertificateIdentified());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		super.checkPdfRevision(diagnosticData);
		
		Set<SignatureWrapper> signatures = diagnosticData.getAllSignatures();
		assertNotNull(signatures);
		for (SignatureWrapper signature : signatures) {
			List<BigInteger> byteRange = signature.getSignatureByteRange();
			assertNotNull(byteRange);
			assertEquals(4, byteRange.size());
			assertEquals(-1, byteRange.get(1).compareTo(byteRange.get(2)));
		}
	}

}
