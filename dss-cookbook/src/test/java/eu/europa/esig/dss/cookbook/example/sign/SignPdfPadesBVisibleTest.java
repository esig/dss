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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.TextWrapping;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.awt.Color;

/**
 * How to sign PDF Document with PAdES-BASELINE-B and include a visual representation
 */
public class SignPdfPadesBVisibleTest extends CookbookTools {

	@Test
	public void signPAdESBaselineBWithVisibleSignature() throws Exception {

		// GET document to be signed -
		// Return DSSDocument toSignDocument
		preparePdfDoc();

		// Get a token connection based on a pkcs12 file commonly used to store private
		// keys with accompanying public key certificates, protected with a password-based
		// symmetric key -
		// Return AbstractSignatureTokenConnection signingToken

		// and it's first private key entry from the PKCS12 store
		// Return DSSPrivateKeyEntry privateKey *****
		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demo[]
			// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
			// import eu.europa.esig.dss.enumerations.SignatureLevel;
			// import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
			// import eu.europa.esig.dss.enumerations.SignerTextPosition;
			// import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
			// import eu.europa.esig.dss.enumerations.TextWrapping;
			// import eu.europa.esig.dss.model.DSSDocument;
			// import eu.europa.esig.dss.model.InMemoryDocument;
			// import eu.europa.esig.dss.model.SignatureValue;
			// import eu.europa.esig.dss.model.ToBeSigned;
			// import eu.europa.esig.dss.pades.DSSFileFont;
			// import eu.europa.esig.dss.pades.DSSFont;
			// import eu.europa.esig.dss.pades.PAdESSignatureParameters;
			// import eu.europa.esig.dss.pades.SignatureFieldParameters;
			// import eu.europa.esig.dss.pades.SignatureImageParameters;
			// import eu.europa.esig.dss.pades.SignatureImageTextParameters;
			// import eu.europa.esig.dss.pades.signature.PAdESService;
			// import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
			// import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
			// import java.awt.Color;

			// tag::parameters-configuration[]
			// Preparing parameters for the PAdES signature
			PAdESSignatureParameters parameters = new PAdESSignatureParameters();
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());

			// Initialize visual signature and configure
			SignatureImageParameters imageParameters = new SignatureImageParameters();
			// set an image
			imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png")));
			
			// initialize signature field parameters
			SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
			imageParameters.setFieldParameters(fieldParameters);
			// the origin is the left and top corner of the page
			fieldParameters.setOriginX(200);
			fieldParameters.setOriginY(400);
			fieldParameters.setWidth(300);
			fieldParameters.setHeight(200);
			// end::parameters-configuration[]
			
			// tag::font[]
			// Initialize text to generate for visual signature
			DSSFont font = new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansRegular.ttf"));
			// end::font[]
			// tag::text[]
			// Instantiates a SignatureImageTextParameters object
			SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
			// Allows you to set a DSSFont object that defines the text style (see more information in the section "Fonts usage")
			textParameters.setFont(font);
			// Defines the text content
			textParameters.setText("My visual signature \n #1");
			// Defines the color of the characters
			textParameters.setTextColor(Color.BLUE);
			// Defines the background color for the area filled out by the text
			textParameters.setBackgroundColor(Color.YELLOW);
			// Defines a padding between the text and a border of its bounding area
			textParameters.setPadding(20);
			// TextWrapping parameter allows defining the text wrapping behavior within  the signature field
			/*
			  FONT_BASED - the default text wrapping, the text is computed based on the given font size;
			  FILL_BOX - finds optimal font size to wrap the text to a signature field box;
			  FILL_BOX_AND_LINEBREAK - breaks the words to multiple lines in order to find the biggest possible font size to wrap the text into a signature field box.
			*/
			textParameters.setTextWrapping(TextWrapping.FONT_BASED);
			// Set textParameters to a SignatureImageParameters object
			imageParameters.setTextParameters(textParameters);
			// end::text[]
			// tag::textImageCombination[]
			// Specifies a text position relatively to an image (Note: applicable only for joint image+text visible signatures). 
			// Thus with _SignerPosition.LEFT_ value, the text will be placed on the left side, 
			// and image will be aligned to the right side inside the signature field
			textParameters.setSignerTextPosition(SignerTextPosition.LEFT);
			// Specifies a horizontal alignment of a text with respect to its area
			textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
			// Specifies a vertical alignment of a text block with respect to a signature field area
			textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
			// end::textImageCombination[]
			// tag::sign[]
			parameters.setImageParameters(imageParameters);

			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create PAdESService for signature
			PAdESService service = new PAdESService(commonCertificateVerifier);
			// tag::custom-factory[]
			service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
			// end::custom-factory[]
			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// We invoke the xadesService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			// end::sign[]

			// end::demo[]

			testFinalDocument(signedDocument);
		}
	}
}
