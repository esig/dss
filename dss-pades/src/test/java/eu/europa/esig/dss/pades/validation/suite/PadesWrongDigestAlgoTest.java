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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PadesWrongDigestAlgoTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/wrong-digest-algo.pdf"));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);

		assertEquals(1, diagnosticData.getAllSignatures().size());
	}
	
	@Override
	protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNull(signature.getDigestAlgorithm());
	}
	
	@Override
	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureById.isSigningCertificateIdentified());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		assertEquals(4, diagnosticData.getTimestampList().size());
		
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
		}
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkDTBSR(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNull(signatureWrapper.getDataToBeSignedRepresentation()); // DigestAlgo is not supported
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		for (AdvancedSignature advancedSignature : advancedSignatures) {
			List<TimestampToken> allTimestamps = advancedSignature.getAllTimestamps();
			for (TimestampToken timestampToken : allTimestamps) {
				TimestampCertificateSource certificateSource = timestampToken.getCertificateSource();
				
				TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampToken.getDSSIdAsString());
				FoundCertificatesProxy foundCertificates = timestampWrapper.foundCertificates();
				
				assertEquals(certificateSource.getSigningCertificateRefs().size(),
						foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size() +
						foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
			}
		}
	}
	
	@Override
	protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
		assertNotNull(signatureIdentifier);
		assertNull(signatureIdentifier.getDigestAlgAndValue());
	}

}
