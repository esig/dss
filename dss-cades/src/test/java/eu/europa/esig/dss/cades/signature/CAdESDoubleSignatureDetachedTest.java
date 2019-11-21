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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DefaultDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESDoubleSignatureDetachedTest extends PKIFactoryAccess {

	private String user;

	@Test
	public void test() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");

		byte[] expectedDigest = Utils.fromBase64(documentToSign.getDigest(DigestAlgorithm.SHA256));

		user = GOOD_USER;
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CAdESService service = new CAdESService(getOfflineCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		user = EE_GOOD_USER;
		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setDetachedContents(Arrays.asList(documentToSign));

		service = new CAdESService(getOfflineCertificateVerifier());

		dataToSign = service.getDataToSign(signedDocument, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument resignedDocument = service.signDocument(signedDocument, signatureParameters, signatureValue);

		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(resignedDocument);
		validator.setDetachedContents(Arrays.asList(documentToSign));
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();

//		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertEquals(2, diagnosticData.getSignatureIdList().size());

		for (String id : diagnosticData.getSignatureIdList()) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(id));

			SignatureWrapper signatureById = diagnosticData.getSignatureById(id);
			List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
			assertEquals(1, digestMatchers.size());

			XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
			assertEquals(DigestMatcherType.MESSAGE_DIGEST, xmlDigestMatcher.getType());
			assertEquals(DigestAlgorithm.SHA256, xmlDigestMatcher.getDigestMethod());
			assertArrayEquals(expectedDigest, xmlDigestMatcher.getDigestValue());
		}

		user = EE_GOOD_USER;
		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		// explicit missing file
		// signatureParameters.setDetachedContents(Arrays.asList(documentToSign));

		final CAdESService service2 = new CAdESService(getOfflineCertificateVerifier());
		final CAdESSignatureParameters params2 = signatureParameters;
		SignatureValue signatureValue2 = signatureValue;

		DSSException e = assertThrows(DSSException.class, () -> {
			service2.getDataToSign(signedDocument, params2);
		});
		assertEquals("Unknown SignedContent", e.getMessage());

		e = assertThrows(DSSException.class, () -> {
			service2.signDocument(signedDocument, params2, signatureValue2);
		});
		assertEquals("Unknown SignedContent", e.getMessage());

	}

	@Override
	protected String getSigningAlias() {
		return user;
	}
}
