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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESTwoSignersLTALevelTest extends PKIFactoryAccess {
	
	private String signingAlias = GOOD_USER;

	@Test
	void test() throws Exception {

		DSSDocument toBeSigned = new InMemoryDocument(PAdESTwoSignersLTALevelTest.class.getResourceAsStream("/sample.pdf"));

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());

		PAdESSignatureParameters params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		signingAlias = RSA_SHA3_USER;
		
		params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		params.setSigningCertificate(getSigningCert());

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);

		validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
		}

		assertEquals(0, diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId()).size());
		
		service.setTspSource(getAlternateGoodTsa());

		params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		params.setIncludeVRIDictionary(true); // include VRI for testing
		DSSDocument ltaDocument = service.extendDocument(doubleSignedDocument, params);

		validator = SignedDocumentValidator.fromDocument(ltaDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		reports = validator.validateDocument();
		diagnosticData = reports.getDiagnosticData();
		
		assertEquals(2, diagnosticData.getSignatures().size());
		assertEquals(2, diagnosticData.getTimestampList().size()); // signature + archive tsts
		
		Set<String> vriOcsps = new HashSet<>();
		Set<String> nonVriOcsps = new HashSet<>();
		
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			int crlCounter = 0;
			int ocspLinkedCounter = 0;
			int ocspNotLinkedCounter = 0;
			
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
			assertEquals(SignatureLevel.PAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(signatureWrapper.getId()));
			assertEquals(0, signatureWrapper.foundRevocations().getOrphanRevocationData().size());
			
			List<RelatedRevocationWrapper> allFoundRevocations = signatureWrapper.foundRevocations().getRelatedRevocationData();
			for (RelatedRevocationWrapper foundRevocation : allFoundRevocations) {
				if (RevocationType.CRL.equals(foundRevocation.getRevocationType())) {
					++crlCounter;
				} else {
					assertTrue(Utils.isCollectionNotEmpty(foundRevocation.getOrigins()));
					if (foundRevocation.getOrigins().contains(RevocationOrigin.VRI_DICTIONARY)) {
						vriOcsps.add(foundRevocation.getId());
						++ocspLinkedCounter;
					} else {
						nonVriOcsps.add(foundRevocation.getId());
						++ ocspNotLinkedCounter;
					}
				}
			}
			
			assertEquals(1, crlCounter);
			assertEquals(1, ocspLinkedCounter);
			assertEquals(1, ocspNotLinkedCounter);
		}

		// contain revocations related to each other
		assertEquals(2, vriOcsps.size());
		assertEquals(2, nonVriOcsps.size());
		assertEquals(vriOcsps, nonVriOcsps);

	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

}
