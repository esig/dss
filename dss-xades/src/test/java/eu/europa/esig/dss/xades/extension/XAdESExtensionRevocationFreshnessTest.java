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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESExtensionRevocationFreshnessTest extends PKIFactoryAccess {
	
	private DSSDocument documentToSign;
	private CertificateVerifier certificateVerifier;
	private String signingAlias;
	private XAdESSignatureParameters signatureParameters;
	
	@BeforeEach
	public void init() {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		// avoid caching
		certificateVerifier = getOfflineCertificateVerifier();
		certificateVerifier.setAIASource(new DefaultAIASource());
		certificateVerifier.setCrlSource(new OnlineCRLSource());
		certificateVerifier.setOcspSource(new OnlineOCSPSource());

		signingAlias = EE_GOOD_USER;
		
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
	}

	@AfterEach
	public void after() {
		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new LogOnStatusAlert());
	}
	
	@Test
	public void noExceptionTest() {
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		
		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new LogOnStatusAlert());

		XAdESService service = new XAdESService(certificateVerifier);
        service.setTspSource(getAlternateGoodTsa());

		DSSDocument signedDocument = sign(service, documentToSign);
		
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		DSSDocument extendedDocument = service.extendDocument(signedDocument, signatureParameters);
		
		validate(extendedDocument);
	}
	
	@Test
	public void throwExceptionOnNoRevocationAfterBestSignatureTimeTest() {
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new LogOnStatusAlert());

		XAdESService service = new XAdESService(certificateVerifier);
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(signatureParameters.bLevel().getSigningDate());
		calendar.add(1, Calendar.MINUTE);
		service.setTspSource(getGoodTsaByTime(calendar.getTime()));

		DSSDocument signedDocument = sign(service, documentToSign);

		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		Exception exception = assertThrows(AlertException.class, () ->
				service.extendDocument(signedDocument, signatureParameters));
		assertTrue(exception.getMessage().contains("Fresh revocation data is missing for one or more certificate(s)."));
		assertTrue(exception.getMessage().contains("No revocation data found after the best signature time"));
	}

	@Test
	public void throwExceptionOnUncoveredPOETest() {
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new ExceptionOnStatusAlert());

		XAdESService service = new XAdESService(certificateVerifier);
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(signatureParameters.bLevel().getSigningDate());
		calendar.add(1, Calendar.MINUTE);
		service.setTspSource(getGoodTsaByTime(calendar.getTime()));

		DSSDocument signedDocument = sign(service, documentToSign);

		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		Exception exception = assertThrows(AlertException.class, () ->
				service.extendDocument(signedDocument, signatureParameters));
		assertTrue(exception.getMessage().contains("Revocation data is missing for one or more POE(s)."));
		assertTrue(exception.getMessage().contains("No revocation data found after the best signature time"));
	}
	
	@Test
	public void throwExceptionWithDelayTest() throws Exception {
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new ExceptionOnStatusAlert());

		XAdESService service = new XAdESService(certificateVerifier);
        service.setTspSource(getAlternateGoodTsa());

		DSSDocument signedDocument = sign(service, documentToSign);
		
		// wait one second
		Calendar nextSecond = Calendar.getInstance();
		nextSecond.add(Calendar.SECOND, 1);
		await().atMost(2, TimeUnit.SECONDS).until(() -> Calendar.getInstance().getTime().compareTo(nextSecond.getTime()) > 0);
		
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		DSSDocument extendedDocument = service.extendDocument(signedDocument, signatureParameters);
		
		validate(extendedDocument);
	}
	
	private DSSDocument sign(XAdESService service, DSSDocument doc) {
		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}
	
	private void validate(DSSDocument doc) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

}