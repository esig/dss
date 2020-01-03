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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class DSS1334Test extends PKIFactoryAccess {

	private static final String ORIGINAL_FILE = "src/test/resources/validation/dss1334/simple-test.xml";

	@BeforeAll
	public static void encodingTest() {
		// be careful about carriage returns windows/linux
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1334/simple-test.xml");
		assertEquals("tl08+/KLCeJN8RRCEDzF8aJ12Ew=", doc.getDigest(DigestAlgorithm.SHA1));
		// Hex content :
		// 3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0d0a3c746573743e0d0a093c74657374456c656d656e743e746573743c2f74657374456c656d656e743e0d0a3c2f746573743e0d0a
	}

	@Test
	public void test1() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		// not valid : reference with empty URI -> not detached signature
		assertFalse(signature.isBLevelTechnicallyValid());
	}

	@Test
	public void testDSS1468() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		FileDocument fileDocument = new FileDocument(ORIGINAL_FILE);
		fileDocument.setName(null);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(fileDocument));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		// not valid : reference with empty URI -> not detached signature
		assertFalse(signature.isBLevelTechnicallyValid());
	}

	@Test
	public void extendInvalidFile() {
		Exception exception = assertThrows(DSSException.class, () -> {
			DSSDocument doc = new FileDocument(
					"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");

			XAdESService service = new XAdESService(new CommonCertificateVerifier());
			service.setTspSource(getGoodTsa());

			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
			parameters.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));
			service.extendDocument(doc, parameters);
		});
		assertEquals("Cryptographic signature verification has failed / Certificate #1: Signature verification failed", exception.getMessage());
	}

	@Test
	public void test2() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/simple-test-signed-xades-baseline-b.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
	}

	@Test
	public void extendValidFile() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/simple-test-signed-xades-baseline-b.xml");

		XAdESService service = new XAdESService(new CommonCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		parameters.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));
		assertNotNull(service.extendDocument(doc, parameters));
	}

	@Test
	public void test3() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/simple-test.signed-only-detached-LuxTrustCA3.xml");
		assertCryptoValid(doc);
	}

	private void assertCryptoValid(DSSDocument doc) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
	}

	@Test
	public void signWithDSS() throws IOException {
		FileDocument fileDocument = new FileDocument(ORIGINAL_FILE);
		fileDocument.setName(null);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		
		ToBeSigned dataToSign = service.getDataToSign(fileDocument, parameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		DSSDocument signDocument = service.signDocument(fileDocument, parameters, signatureValue);

		String stringContent = new String(DSSUtils.toByteArray(signDocument), "UTF-8");
		assertTrue(stringContent.contains("<ds:Reference Id=\"r-id-")); // no empty URI

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signDocument);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
