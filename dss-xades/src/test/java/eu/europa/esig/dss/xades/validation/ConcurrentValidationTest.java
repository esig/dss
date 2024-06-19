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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.OCSPFirstRevocationDataLoadingStrategyFactory;
import eu.europa.esig.dss.spi.validation.RevocationDataLoadingStrategyFactory;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Test DSS with multi threads
 * 
 */
public class ConcurrentValidationTest extends PKIFactoryAccess {

	private static final Logger LOG = LoggerFactory.getLogger(ConcurrentValidationTest.class);

	private String signingAlias;

	@Test
	public void test() {

		ExecutorService executor = Executors.newFixedThreadPool(20);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setAIASource(new DefaultAIASource());

		List<Future<Boolean>> futures = new ArrayList<>();

		for (int i = 0; i < 200; i++) {
			futures.add(executor.submit(new TestConcurrent(certificateVerifier)));
		}

		for (Future<Boolean> future : futures) {
			try {
				assertTrue(future.get());
			} catch (Exception e) {
				LOG.error(e.getMessage(), e);
			}
		}

		executor.shutdown();
	}

	private static class TestConcurrent implements Callable<Boolean> {

		private final CertificateVerifier certificateVerifier;

		public TestConcurrent(CertificateVerifier certificateVerifier) {
			this.certificateVerifier = certificateVerifier;
		}

		@Override
		public Boolean call() throws Exception {
			DSSDocument doc = new FileDocument("src/test/resources/dss-817-test.xml");
			SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
			validator.setSignaturePolicyProvider(new SignaturePolicyProvider());
			validator.setCertificateVerifier(certificateVerifier);

			return validator.validateDocument() != null;
		}

	}

	@Test
	public void onlineValidationTest() {
		final DSSDocument documentToSign = new FileDocument("src/test/resources/sample.xml");
		final XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		signingAlias = GOOD_USER;
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getSignatureAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocumentOne = service.signDocument(documentToSign, signatureParameters, signatureValue);

		service.setTspSource(getSHA3GoodTsa());
		signingAlias = RSA_SHA3_USER;
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

		dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getSignatureAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocumentTwo = service.signDocument(documentToSign, signatureParameters, signatureValue);

		RevocationDataLoadingStrategyFactory revocationDataLoadingStrategyFactory = new OCSPFirstRevocationDataLoadingStrategyFactory();

		CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
		completeCertificateVerifier.setRevocationDataLoadingStrategyFactory(revocationDataLoadingStrategyFactory);

		CertificateVerifier offlineCertificateVerifier = getOfflineCertificateVerifier();
		offlineCertificateVerifier.setRevocationDataLoadingStrategyFactory(revocationDataLoadingStrategyFactory);

		ExecutorService executor = Executors.newFixedThreadPool(40);

		List<Future<Boolean>> futures = new ArrayList<>();

		for (int i = 0; i < 200; i++) {
			futures.add(executor.submit(new TestOnlineValidation(completeCertificateVerifier, signedDocumentOne)));
			futures.add(executor.submit(new TestOnlineValidation(offlineCertificateVerifier, signedDocumentTwo)));
		}

		for (Future<Boolean> future : futures) {
			try {
				assertTrue(future.get());
			} catch (Exception e) {
				fail(e);
			}
		}

		executor.shutdown();
	}

	private static class TestOnlineValidation implements Callable<Boolean> {

		private final CertificateVerifier certificateVerifier;

		private final DSSDocument toBeValidated;

		public TestOnlineValidation(CertificateVerifier certificateVerifier, DSSDocument toBeValidated) {
			this.certificateVerifier = certificateVerifier;
			this.toBeValidated = toBeValidated;
		}

		@Override
		public Boolean call() {
			SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toBeValidated);
			validator.setCertificateVerifier(certificateVerifier);

			Reports reports = validator.validateDocument();
			SimpleReport simpleReport = reports.getSimpleReport();
			return Indication.TOTAL_PASSED.equals(simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		}

	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

}
