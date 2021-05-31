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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

@Tag("slow")
public class PAdESVisibleCombinationTextAndImageSignatureTest extends AbstractTestVisualComparator {

	protected PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private String testName;

	private float similarityLimit;
	
	@BeforeEach
	public void init(TestInfo testInfo) {
		testName = testInfo.getTestMethod().get().getName();
		
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());
		similarityLimit = 0;
	}

	@Test
	public void testGeneratedImagePNGWithText() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);

		imageParameters.setZoom(50); // reduces 50%
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	public void testGeneratedImagePNGWithTextOnTop() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	public void testGeneratedImageAndTextOnTop() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getSmallRedJPG());
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(200);
		fieldParameters.setOriginY(300);
		imageParameters.setFieldParameters(fieldParameters);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.BLUE);
		DSSFileFont font = new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf"));
		font.setSize(15);
		textParameters.setFont(font);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}

	@Test
	public void testGeneratedImageWithText() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		similarityLimit = 0.993f;
		signatureParameters.setImageParameters(imageParameters);
		// image and text on left
		drawAndCompareVisually();

		// image and text on right
		imageParameters.getTextParameters().setSignerTextPosition(SignerTextPosition.RIGHT);
		drawAndCompareVisually();

		// image and text on right and horizontal align is right
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
		drawAndCompareVisually();

		// image and text on right and horizontal align is center
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		drawAndCompareVisually();

		// image and text on right and horizontal align is center with transparent colors
		Color transparent = new Color(0, 0, 0, 0.25f);
		imageParameters.getTextParameters().setBackgroundColor(transparent);
		imageParameters.getTextParameters().setTextColor(new Color(0.5f, 0.2f, 0.8f, 0.5f));
		imageParameters.setBackgroundColor(transparent);
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(10);
		fieldParameters.setOriginY(10);
		imageParameters.setFieldParameters(fieldParameters);

		similarityLimit = 0.990f;
		drawAndCompareVisually();

		// image and text on right and horizontal align is center with transparent colors with big image
		imageParameters.setImage(getPngPicture());
		fieldParameters.setWidth(500);
		fieldParameters.setHeight(250);
		drawAndCompareVisually();
		
		// image and text on right and horizontal align is center with transparent colors with big image and vertical
		// align top
		imageParameters.getTextParameters().setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
		drawAndCompareVisually();

		// image and text on right and horizontal align is center with transparent colors with big image and vertical
		// align bottom
		imageParameters.getTextParameters().setSignerTextVerticalAlignment(SignerTextVerticalAlignment.BOTTOM);
		drawAndCompareVisually();

		// image and text on left and horizontal align is center with transparent colors with big image and vertical
		// align bottom
		imageParameters.getTextParameters().setSignerTextPosition(SignerTextPosition.LEFT);
		drawAndCompareVisually();

		// image and text on left and horizontal align is center with transparent colors and vertical align bottom
		imageParameters.setImage(getSmallRedJPG());
		drawAndCompareVisually();
	}

	private SignatureImageParameters createSignatureImageParameters() {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getSmallRedJPG());
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(200);
		fieldParameters.setOriginY(300);
		imageParameters.setFieldParameters(fieldParameters);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setSignerTextPosition(SignerTextPosition.LEFT);
		imageParameters.setTextParameters(textParameters);

		return imageParameters;
	}

	private DSSDocument getSmallRedJPG() {
		return new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG);
	}

	private DSSDocument getPngPicture() {
		return new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG);
	}

	@Override
	protected String getTestName() {
		return testName;
	}

	@Override
	protected PAdESService getService() {
		return service;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected float getSimilarityLimit() {
		if (similarityLimit != 0) {
			return similarityLimit;
		}
		return super.getSimilarityLimit();
	}

}
