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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.RepeatedTest;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESDoubleSignatureTest extends PKIFactoryAccess {

	@RepeatedTest(10)
	public void testDoubleSignature() throws Exception {

		DSSDocument toBeSigned = new InMemoryDocument(PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports1 = validator.validateDocument();

		DiagnosticData diagnosticData1 = reports1.getDiagnosticData();
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA, diagnosticData1.getSignatureFormat(diagnosticData1.getFirstSignatureId()));

		params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		params.setSigningCertificate(getSigningCert());
		service.setTspSource(getAlternateGoodTsa());

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);

		validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports2 = validator.validateDocument();
		DiagnosticData diagnosticData2 = reports2.getDiagnosticData();

		// Bug with 2 signatures which have the same ID
		List<String> signatureIdList = diagnosticData2.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureId));
		}

		assertEquals(3, diagnosticData2.getTimestampIdList(diagnosticData2.getFirstSignatureId()).size());

		checkAllRevocationOnce(diagnosticData2);

		checkAllPreviousRevocationDataInNewDiagnosticData(diagnosticData1, diagnosticData2);
		
		SignatureWrapper signatureOne = diagnosticData2.getSignatures().get(0);
		SignatureWrapper signatureTwo = diagnosticData2.getSignatures().get(1);
		assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(), signatureTwo.getSignatureDigestReference().getDigestValue()));

		List<DSSDocument> originalDocumentsSigOne = validator.getOriginalDocuments(signatureOne.getId());
		assertEquals(1, originalDocumentsSigOne.size());
		assertArrayEquals(DSSUtils.toByteArray(toBeSigned), DSSUtils.toByteArray(originalDocumentsSigOne.get(0)));

		List<DSSDocument> originalDocumentsSigTwo = validator.getOriginalDocuments(signatureTwo.getId());
		assertEquals(1, originalDocumentsSigTwo.size());

		validator = SignedDocumentValidator.fromDocument(originalDocumentsSigTwo.get(0));
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signatureOne.getId());
		assertEquals(1, originalDocuments.size());
		assertArrayEquals(DSSUtils.toByteArray(originalDocumentsSigOne.get(0)), DSSUtils.toByteArray(originalDocuments.get(0)));

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		Reports reports3 = validator.validateDocument();
		DiagnosticData diagnosticData3 = reports3.getDiagnosticData();
		assertTrue(diagnosticData3.isBLevelTechnicallyValid(signatures.get(0).getId()));
	}

	private void checkAllPreviousRevocationDataInNewDiagnosticData(DiagnosticData diagnosticData1, DiagnosticData diagnosticData2) {

		Set<RevocationWrapper> allRevocationData1 = diagnosticData1.getAllRevocationData();
		Set<RevocationWrapper> allRevocationData2 = diagnosticData2.getAllRevocationData();

		for (RevocationWrapper revocationWrapper : allRevocationData1) {
			boolean found = false;
			for (RevocationWrapper revocationWrapper2 : allRevocationData2) {
				if (Utils.areStringsEqual(revocationWrapper.getId(), revocationWrapper2.getId())) {
					found = true;
				}
			}
			assertTrue(found);
		}
	}

	private void checkAllRevocationOnce(DiagnosticData diagnosticData) {
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper certificateWrapper : usedCertificates) {
			if (certificateWrapper.isTrusted() || certificateWrapper.isSelfSigned() || certificateWrapper.isIdPkixOcspNoCheck()) {
				continue;
			}
			int nbRevoc = certificateWrapper.getCertificateRevocationData().size();
			assertEquals(1, nbRevoc, "Nb revoc for cert " + certificateWrapper.getCommonName() + " = " + nbRevoc);
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
