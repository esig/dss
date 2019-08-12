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
package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.Assert.assertTrue;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESVisibleSignature extends PKIFactoryAccess {

	private DocumentSignatureService<PAdESSignatureParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
	}

	@Test
	public void testGeneratedTextOnly() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnly() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getSmallRedJPG());
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnlyPNG() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnlyPNGWithSize() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getSmallRedJPG());
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		imageParameters.setWidth(50);
		imageParameters.setHeight(50);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	@Test
	public void testGeneratedImageOnlyPngUnZoom() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		imageParameters.setZoom(50); // reduces 50%
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate();
	}

	private void signAndValidate() throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	private DSSDocument getSmallRedJPG() {
		return new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG);
	}

	private DSSDocument getPngPicture() {
		return new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG);
	}

}
