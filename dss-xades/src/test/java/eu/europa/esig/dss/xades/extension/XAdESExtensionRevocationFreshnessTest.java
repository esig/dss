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

import eu.europa.esig.dss.alert.AbstractStatusAlert;
import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.status.Status;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.spi.validation.status.RevocationFreshnessStatus;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESExtensionRevocationFreshnessTest extends PKIFactoryAccess {
	
	private DSSDocument documentToSign;
	private CertificateVerifier certificateVerifier;
	private String signingAlias;
	private XAdESSignatureParameters signatureParameters;
	
	@BeforeEach
	void init() {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		// avoid caching
		certificateVerifier = getOfflineCertificateVerifier();
		certificateVerifier.setAIASource(pkiAIASource());
		certificateVerifier.setCrlSource(pkiCRLSource());
		certificateVerifier.setOcspSource(pkiOCSPSource());

		signingAlias = EE_GOOD_USER;
		
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
	}

	@AfterEach
	void after() {
		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new LogOnStatusAlert());
	}
	
	@Test
	void noExceptionTest() {
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
	void throwExceptionOnNoRevocationAfterBestSignatureTimeTest() {
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new LogOnStatusAlert());

		XAdESService service = new XAdESService(certificateVerifier);
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(signatureParameters.bLevel().getSigningDate());
		calendar.add(Calendar.DAY_OF_MONTH, 1);
		service.setTspSource(getGoodTsaByTime(calendar.getTime()));

		DSSDocument signedDocument = sign(service, documentToSign);

		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		Exception exception = assertThrows(AlertException.class, () ->
				service.extendDocument(signedDocument, signatureParameters));
		assertTrue(exception.getMessage().contains("Fresh revocation data is missing for one or more certificate(s)."));
		assertTrue(exception.getMessage().contains(getSigningCert().getDSSIdAsString()));
		assertTrue(exception.getMessage().contains("No revocation data found after the best signature time"));
	}

	@Test
	void throwExceptionOnUncoveredPOETest() {
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new ExceptionOnStatusAlert());

		XAdESService service = new XAdESService(certificateVerifier);
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(signatureParameters.bLevel().getSigningDate());
		calendar.add(Calendar.DAY_OF_MONTH, 1);
		service.setTspSource(getGoodTsaByTime(calendar.getTime()));

		DSSDocument signedDocument = sign(service, documentToSign);

		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		Exception exception = assertThrows(AlertException.class, () ->
				service.extendDocument(signedDocument, signatureParameters));
		assertTrue(exception.getMessage().contains("Revocation data is missing for one or more POE(s)."));
		assertFalse(exception.getMessage().contains(getSigningCert().getDSSIdAsString()));
		assertTrue(exception.getMessage().contains("No revocation data found after the best signature time"));
	}
	
	@Test
	void throwExceptionWithDelayTest() {
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new ExceptionOnStatusAlert());

		XAdESService service = new XAdESService(certificateVerifier);
		// ensure the time is synchronized between the TSP and revocation data
        service.setTspSource(getPKITSPSourceByName(EE_GOOD_TSA));

		DSSDocument signedDocument = sign(service, documentToSign);
		
		// wait one second
		awaitOneSecond();
		
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		DSSDocument extendedDocument = service.extendDocument(signedDocument, signatureParameters);
		
		validate(extendedDocument);
	}

	@Test
	void throwExceptionOnNoRevocationAfterBestSignatureTimeEnsureNextUpdateTimeTest() {
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		RevocationFreshnessStatusCheckAlertHandlerCallback callback = new RevocationFreshnessStatusCheckAlertHandlerCallback();
		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new AbstractStatusAlert(callback) {});

		XAdESService service = new XAdESService(certificateVerifier);
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(signatureParameters.bLevel().getSigningDate());
		calendar.add(Calendar.DAY_OF_MONTH, 1);
		service.setTspSource(getGoodTsaByTime(calendar.getTime()));

		DSSDocument signedDocument = sign(service, documentToSign);

		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		service.extendDocument(signedDocument, signatureParameters);

		Status statusCallback = callback.status;
		assertNotNull(statusCallback);

		assertTrue(statusCallback instanceof RevocationFreshnessStatus);
		RevocationFreshnessStatus revocationFreshnessStatus = (RevocationFreshnessStatus) statusCallback;

		String message = revocationFreshnessStatus.getMessage();
		assertTrue(Utils.isStringNotEmpty(message));

		Date minimalNextUpdateTime = revocationFreshnessStatus.getMinimalNextUpdateTime();
		assertNotNull(minimalNextUpdateTime);

		String errorString = revocationFreshnessStatus.getErrorString();
		assertTrue(Utils.isStringNotEmpty(errorString));
		assertTrue(errorString.contains(message));
		assertTrue(errorString.contains(DSSUtils.formatDateToRFC(minimalNextUpdateTime)));

		Collection<Token> relatedTokens = revocationFreshnessStatus.getRelatedTokens();
		assertEquals(1, relatedTokens.size());
		Collection<String> relatedObjectIds = revocationFreshnessStatus.getRelatedObjectIds();
		assertEquals(1, relatedObjectIds.size());
		assertEquals(new HashSet<>(relatedObjectIds), relatedTokens.stream().map(Token::getDSSIdAsString).collect(Collectors.toSet()));

		Token token = relatedTokens.iterator().next();
		assertTrue(token instanceof CertificateToken);

		String tokenErrorMessage = revocationFreshnessStatus.getMessageForToken(token);
		assertTrue(Utils.isStringNotEmpty(tokenErrorMessage));
		String messageForObjectWithId = revocationFreshnessStatus.getMessageForObjectWithId(token.getDSSIdAsString());
		assertTrue(Utils.isStringNotEmpty(messageForObjectWithId));
		assertEquals(tokenErrorMessage, messageForObjectWithId);

		assertTrue(errorString.contains(token.getDSSIdAsString()));
		assertTrue(errorString.contains(tokenErrorMessage));
	}

	@Test
	void throwExceptionOnNoRevocationAfterBestSignatureTimeStatusTest() {
		signingAlias = GOOD_USER_WITH_PEM_CRL;

		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		RevocationFreshnessStatusCheckAlertHandlerCallback callback = new RevocationFreshnessStatusCheckAlertHandlerCallback();
		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new AbstractStatusAlert(callback) {});

		XAdESService service = new XAdESService(certificateVerifier);
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(signatureParameters.bLevel().getSigningDate());
		calendar.add(Calendar.DAY_OF_MONTH, 1);
		service.setTspSource(getGoodTsaByTime(calendar.getTime()));

		DSSDocument signedDocument = sign(service, documentToSign);

		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		service.extendDocument(signedDocument, signatureParameters);

		Status statusCallback = callback.status;
		assertNotNull(statusCallback);

		assertTrue(statusCallback instanceof RevocationFreshnessStatus);
		RevocationFreshnessStatus revocationFreshnessStatus = (RevocationFreshnessStatus) statusCallback;

		String message = revocationFreshnessStatus.getMessage();
		assertTrue(Utils.isStringNotEmpty(message));

		Date minimalNextUpdateTime = revocationFreshnessStatus.getMinimalNextUpdateTime();
		assertNotNull(minimalNextUpdateTime);

		String errorString = revocationFreshnessStatus.getErrorString();
		assertTrue(Utils.isStringNotEmpty(errorString));
		assertTrue(errorString.contains(message));
		assertTrue(errorString.contains(DSSUtils.formatDateToRFC(minimalNextUpdateTime)));

		Collection<Token> relatedTokens = revocationFreshnessStatus.getRelatedTokens();
		assertEquals(2, relatedTokens.size());
		Collection<String> relatedObjectIds = revocationFreshnessStatus.getRelatedObjectIds();
		assertEquals(2, relatedObjectIds.size());
		assertEquals(new HashSet<>(relatedObjectIds), relatedTokens.stream().map(Token::getDSSIdAsString).collect(Collectors.toSet()));

		for (Token token : relatedTokens) {
			String tokenErrorMessage = revocationFreshnessStatus.getMessageForToken(token);
			assertTrue(Utils.isStringNotEmpty(tokenErrorMessage));
			String messageForObjectWithId = revocationFreshnessStatus.getMessageForObjectWithId(token.getDSSIdAsString());
			assertTrue(Utils.isStringNotEmpty(messageForObjectWithId));
			assertEquals(tokenErrorMessage, messageForObjectWithId);

			assertTrue(errorString.contains(token.getDSSIdAsString()));
			assertTrue(errorString.contains(tokenErrorMessage));
		}
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

	private static class RevocationFreshnessStatusCheckAlertHandlerCallback implements AlertHandler<Status> {

		private Status status;

		@Override
		public void process(Status status) {
			this.status = status;
		}

	}

}