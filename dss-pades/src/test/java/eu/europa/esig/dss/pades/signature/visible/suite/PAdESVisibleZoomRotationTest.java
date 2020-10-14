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
package eu.europa.esig.dss.pades.signature.visible.suite;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESVisibleZoomRotationTest extends PKIFactoryAccess {

	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());
	}
	
	@Test
	public void testNoTransformations() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getRedBox());
		
	    SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
	    fieldParameters.setOriginX(20);
	    fieldParameters.setOriginY(50);
	    fieldParameters.setWidth(100);
	    fieldParameters.setHeight(300);
	    imageParameters.setFieldParameters(fieldParameters);
	    
		signatureParameters.setImageParameters(imageParameters);
		
		signAndValidate();
	}
	
	@Test
	public void testZoomOnly() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getRedBox());
		
	    SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
	    fieldParameters.setOriginX(20);
	    fieldParameters.setOriginY(50);
	    fieldParameters.setWidth(100);
	    fieldParameters.setHeight(300);
	    imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setZoom(200);
		signatureParameters.setImageParameters(imageParameters);
		
		signAndValidate();
	}
	
	@Test
	public void testRotationOnly() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getRedBox());

	    SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
	    fieldParameters.setOriginX(20);
	    fieldParameters.setOriginY(50);
	    fieldParameters.setWidth(100);
	    fieldParameters.setHeight(300);
	    imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setImageParameters(imageParameters);
		
		signAndValidate();
	}
	
	@Test
	public void testZoomAndRotation() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getRedBox());

	    SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
	    fieldParameters.setOriginX(20);
	    fieldParameters.setOriginY(50);
	    fieldParameters.setWidth(100);
	    fieldParameters.setHeight(300);
	    imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setZoom(200);
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setImageParameters(imageParameters);
		
		signAndValidate();
	}

	private void signAndValidate() throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	private DSSDocument getRedBox() {
		return new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
