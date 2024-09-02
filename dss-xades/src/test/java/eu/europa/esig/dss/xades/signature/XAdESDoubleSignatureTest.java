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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.RepeatedTest;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESDoubleSignatureTest extends PKIFactoryAccess {

	@RepeatedTest(10)
	void testDoubleSignature() throws Exception {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());

		awaitOneSecond();

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTest.xml");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
			assertFalse(diagnosticData.getSignatureById(signatureId).isSignatureDuplicated());
		}
		
		assertEquals(4, diagnosticData.getTimestampList().size());

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
		
		SignatureWrapper signatureOne = diagnosticData.getSignatures().get(0);
		SignatureWrapper signatureTwo = diagnosticData.getSignatures().get(1);
		assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(), signatureTwo.getSignatureDigestReference().getDigestValue()));
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		for (String signatureId : simpleReport.getSignatureIdList()) {
			assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));
		}

		List<DSSDocument> originals = validator.getOriginalDocuments(signatureIdList.get(0));
		assertEquals(1, originals.size());
		DSSDocument original = originals.get(0);
		String firstDocument = new String(XMLCanonicalizer.createInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS).canonicalize(DSSUtils.toByteArray(toBeSigned)));
		String secondDocument = new String(XMLCanonicalizer.createInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS).canonicalize(DSSUtils.toByteArray(original)));
		assertEquals(firstDocument, secondDocument);

		originals = validator.getOriginalDocuments(signatureIdList.get(1));
		assertEquals(1, originals.size());
		original = originals.get(0);
		firstDocument = new String(XMLCanonicalizer.createInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS).canonicalize(DSSUtils.toByteArray(toBeSigned)));
		secondDocument = new String(XMLCanonicalizer.createInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS).canonicalize(DSSUtils.toByteArray(original)));
		assertEquals(firstDocument, secondDocument);
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
