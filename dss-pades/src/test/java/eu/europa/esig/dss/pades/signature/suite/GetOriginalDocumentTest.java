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
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class GetOriginalDocumentTest extends PKIFactoryAccess {

	private static final Logger LOG = LoggerFactory.getLogger(GetOriginalDocumentTest.class);

	@Test
	final void getOriginalDocument() throws Exception {
		DSSDocument document = new InMemoryDocument(GetOriginalDocumentTest.class.getResourceAsStream("/sample.pdf"), "sample.pdf", MimeTypeEnum.PDF);

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		PAdESService service = new PAdESService(getOfflineCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		dataToSign = service.getDataToSign(signedDocument, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		final DSSDocument resignedDocument = service.signDocument(signedDocument, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(resignedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());

		long start = System.currentTimeMillis();
		List<DSSDocument> results = validator.getOriginalDocuments(signatureIdList.get(0));
		long end = System.currentTimeMillis();
		LOG.info("Duration : {} ms", end - start);

		assertEquals(1, results.size());
		DSSDocument retrievedSignedDocument = results.get(0);

		LOG.info("ORIGINAL : {}", Utils.toBase64(document.getDigestValue(DigestAlgorithm.SHA256)));
		LOG.info("RETRIEVED : {}", Utils.toBase64(retrievedSignedDocument.getDigestValue(DigestAlgorithm.SHA256)));

		assertArrayEquals(document.getDigestValue(DigestAlgorithm.SHA256), retrievedSignedDocument.getDigestValue(DigestAlgorithm.SHA256));

		start = System.currentTimeMillis();
		results = validator.getOriginalDocuments(signatureIdList.get(1));
		end = System.currentTimeMillis();
		LOG.info("Duration : {} ms", end - start);

		assertEquals(1, results.size());
		DSSDocument retrievedResignedDocument = results.get(0);

		LOG.info("SIGNED ORIGINAL : {}", Utils.toBase64(signedDocument.getDigestValue(DigestAlgorithm.SHA256)));
		LOG.info("SIGNED RETRIEVED : {}", Utils.toBase64(retrievedResignedDocument.getDigestValue(DigestAlgorithm.SHA256)));

		assertArrayEquals(signedDocument.getDigestValue(DigestAlgorithm.SHA256), retrievedResignedDocument.getDigestValue(DigestAlgorithm.SHA256));
		
		SignatureWrapper firstSignature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(firstSignature);
		List<XmlSignatureScope> firstSignatureScopes = firstSignature.getSignatureScopes();
		assertNotNull(firstSignatureScopes);
		assertEquals(1, firstSignatureScopes.size());
		XmlSignatureScope originalDocumentSignatureScope = firstSignatureScopes.get(0);
		assertNotNull(originalDocumentSignatureScope);
		assertNotNull(originalDocumentSignatureScope.getName());
		assertNotNull(originalDocumentSignatureScope.getScope());
		assertNotNull(originalDocumentSignatureScope.getSignerData());
		XmlDigestAlgoAndValue originalDocDigestAlgoAndValue = originalDocumentSignatureScope.getSignerData().getDigestAlgoAndValue();
		assertNotNull(originalDocDigestAlgoAndValue);
		DigestAlgorithm digestAlgorithmOriginalDocument = originalDocDigestAlgoAndValue.getDigestMethod();
		assertNotNull(digestAlgorithmOriginalDocument);
        assertArrayEquals(document.getDigestValue(digestAlgorithmOriginalDocument), originalDocDigestAlgoAndValue.getDigestValue());
		
		SignatureWrapper secondSignature = diagnosticData.getSignatures().get(1);
		assertNotNull(secondSignature);
		List<XmlSignatureScope> secondSignatureScopes = secondSignature.getSignatureScopes();
		assertNotNull(secondSignatureScopes);
		assertEquals(1, secondSignatureScopes.size());
		XmlSignatureScope firstSignedDocumentSignatureScope = secondSignatureScopes.get(0);
		assertNotNull(firstSignedDocumentSignatureScope);
		assertNotNull(firstSignedDocumentSignatureScope.getName());
		assertNotNull(firstSignedDocumentSignatureScope.getScope());
		assertNotNull(firstSignedDocumentSignatureScope.getSignerData());
		XmlDigestAlgoAndValue firstDocDigestAlgoAndValue = firstSignedDocumentSignatureScope.getSignerData().getDigestAlgoAndValue();
		assertNotNull(firstDocDigestAlgoAndValue);
		DigestAlgorithm digestAlgorithmSignedDocument = firstDocDigestAlgoAndValue.getDigestMethod();
		assertNotNull(digestAlgorithmSignedDocument);
		assertArrayEquals(signedDocument.getDigestValue(digestAlgorithmSignedDocument), firstDocDigestAlgoAndValue.getDigestValue());
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
