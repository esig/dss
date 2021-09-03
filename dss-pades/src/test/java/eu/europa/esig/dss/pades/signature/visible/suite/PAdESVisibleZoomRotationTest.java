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

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESVisibleZoomRotationTest extends AbstractPAdESTestSignature {

	private final DSSDocument RED_CROSS_IMAGE = new InMemoryDocument(
			getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG);

	private final DSSDocument PNG_IMAGE = new InMemoryDocument(
			getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG);

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
		imageParameters.setImage(RED_CROSS_IMAGE);
		
	    SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
	    fieldParameters.setOriginX(20);
	    fieldParameters.setOriginY(50);
	    fieldParameters.setWidth(100);
	    fieldParameters.setHeight(300);
	    imageParameters.setFieldParameters(fieldParameters);
	    
		signatureParameters.setImageParameters(imageParameters);

		super.signAndVerify();
	}
	
	@Test
	public void testZoomOnly() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(RED_CROSS_IMAGE);
		
	    SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
	    fieldParameters.setOriginX(20);
	    fieldParameters.setOriginY(50);
	    fieldParameters.setWidth(100);
	    fieldParameters.setHeight(300);
	    imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setZoom(200);
		signatureParameters.setImageParameters(imageParameters);

		super.signAndVerify();
	}
	
	@Test
	public void testRotationOnly() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(PNG_IMAGE);

	    SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
	    fieldParameters.setOriginX(20);
	    fieldParameters.setOriginY(50);
	    fieldParameters.setWidth(100);
	    fieldParameters.setHeight(300);
	    imageParameters.setFieldParameters(fieldParameters);
	    imageParameters.setBackgroundColor(Color.PINK);
		
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setImageParameters(imageParameters);

		super.signAndVerify();
	}
	
	@Test
	public void testZoomAndRotation() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(PNG_IMAGE);

	    SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
	    fieldParameters.setOriginX(20);
	    fieldParameters.setOriginY(50);
	    fieldParameters.setWidth(100);
	    fieldParameters.setHeight(300);
	    imageParameters.setFieldParameters(fieldParameters);
		imageParameters.setBackgroundColor(Color.PINK);
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
		
		imageParameters.setZoom(200);
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(AlertException.class, () -> super.signAndVerify());
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setHeight(200);
		super.signAndVerify();
	}

	@Override
	public void signAndVerify() {
		// do nothing
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
