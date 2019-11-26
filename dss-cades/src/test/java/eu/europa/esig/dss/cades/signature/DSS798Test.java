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
package eu.europa.esig.dss.cades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.Date;

import org.junit.jupiter.api.Test;

import com.google.common.base.Charsets;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS798Test extends PKIFactoryAccess {

	@Test
	public void testExtendDetachedWithoutFile() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello".getBytes(Charsets.UTF_8), "bin.bin");

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());

		// Level B
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// Level T without detached document
		CAdESService serviceExtend = new CAdESService(getCompleteCertificateVerifier());
		serviceExtend.setTspSource(getGoodTsa());

		CAdESSignatureParameters parametersExtend = new CAdESSignatureParameters();
		parametersExtend.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		assertThrows(DSSException.class, () -> serviceExtend.extendDocument(signedDocument, parametersExtend));
	}

	@Test
	public void testExtendDetachedWithFile() throws Exception {

		DSSDocument documentToSign = new InMemoryDocument("Hello".getBytes(Charsets.UTF_8), "bin.bin");

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());

		// Level B
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// Level T with detached document
		CAdESService serviceExtend = new CAdESService(getCompleteCertificateVerifier());
		serviceExtend.setTspSource(getGoodTsa());

		CAdESSignatureParameters parametersExtend = new CAdESSignatureParameters();
		parametersExtend.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		parametersExtend.setDetachedContents(Arrays.asList(documentToSign));
		DSSDocument extendedDocument = serviceExtend.extendDocument(signedDocument, parametersExtend);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(documentToSign));
		Reports reports = validator.validateDocument();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureLevel.CAdES_BASELINE_T, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
