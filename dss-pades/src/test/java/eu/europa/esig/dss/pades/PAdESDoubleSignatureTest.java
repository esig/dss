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
package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

@RunWith(Parameterized.class)
public class PAdESDoubleSignatureTest extends PKIFactoryAccess {

	@Parameters
	public static List<Object[]> data() {
		return Arrays.asList(new Object[10][0]);
	}

	public PAdESDoubleSignatureTest() {
	}

	@Test
	public void testDoubleSignature() throws Exception {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.pdf"));

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		params.setSigningCertificate(getSigningCert());
		service.setTspSource(getAlternateGoodTsa());

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		// Bug with 2 signatures which have the same ID
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
