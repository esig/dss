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
package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertEquals;

import java.util.Date;
import java.util.List;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class GetOriginalDocument extends PKIFactoryAccess {

	private static final Logger LOG = LoggerFactory.getLogger(GetOriginalDocument.class);

	@Test
	public final void getOriginalDocument() throws Exception {
		DSSDocument document = new InMemoryDocument(GetOriginalDocument.class.getResourceAsStream("/sample.pdf"), "sample.pdf", MimeType.PDF);

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		dataToSign = service.getDataToSign(signedDocument, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		final DSSDocument resignedDocument = service.signDocument(signedDocument, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(resignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
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

		LOG.info("ORIGINAL : {}", document.getDigest(DigestAlgorithm.SHA256));
		LOG.info("RETRIEVED : {}", retrievedSignedDocument.getDigest(DigestAlgorithm.SHA256));

		assertEquals(document.getDigest(DigestAlgorithm.SHA256), retrievedSignedDocument.getDigest(DigestAlgorithm.SHA256));

		start = System.currentTimeMillis();
		results = validator.getOriginalDocuments(signatureIdList.get(1));
		end = System.currentTimeMillis();
		LOG.info("Duration : {} ms", end - start);

		assertEquals(1, results.size());
		DSSDocument retrievedResignedDocument = results.get(0);

		LOG.info("SIGNED ORIGINAL : {}", signedDocument.getDigest(DigestAlgorithm.SHA256));
		LOG.info("SIGNED RETRIEVED : {}", retrievedResignedDocument.getDigest(DigestAlgorithm.SHA256));

		assertEquals(signedDocument.getDigest(DigestAlgorithm.SHA256), retrievedResignedDocument.getDigest(DigestAlgorithm.SHA256));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
