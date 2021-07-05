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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DSS798Test extends PKIFactoryAccess {

	@Test
	public void testExtendDetachedWithoutFile() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello".getBytes(StandardCharsets.UTF_8), "bin.bin");

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());

		// Level B
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// Level T without detached document
		XAdESService serviceExtend = new XAdESService(getOfflineCertificateVerifier());
		serviceExtend.setTspSource(getGoodTsa());

		XAdESSignatureParameters parametersExtend = new XAdESSignatureParameters();
		parametersExtend.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		assertThrows(DSSException.class, () -> serviceExtend.extendDocument(signedDocument, parametersExtend));
	}

	@Test
	public void testExtendDetachedWithFile() throws Exception {

		DSSDocument documentToSign = new InMemoryDocument("Hello".getBytes(StandardCharsets.UTF_8), "bin.bin");

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());

		// Level B
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// Level T with detached document
		XAdESService serviceExtend = new XAdESService(getOfflineCertificateVerifier());
		serviceExtend.setTspSource(getGoodTsa());

		XAdESSignatureParameters parametersExtend = new XAdESSignatureParameters();
		parametersExtend.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		parametersExtend.setDetachedContents(Arrays.asList(documentToSign));
		DSSDocument extendedDocument = serviceExtend.extendDocument(signedDocument, parametersExtend);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(documentToSign));
		Reports reports = validator.validateDocument();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureLevel.XAdES_BASELINE_T, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
