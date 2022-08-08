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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.DSSJavaFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.awt.Font;

/**
 * How to sign PDF Document with PAdES-BASELINE-B and include a visual representation
 */
public class SignPdfPadesBVisibleExistingTest extends CookbookTools {

	@Test
	public void signPAdESBaselineBWithExistingVisibleSignature() throws Exception {

		// GET document to be signed -
		// Return DSSDocument toSignDocument
		preparePdfDoc();

		// Get a token connection based on a pkcs12 file commonly used to store private
		// keys with accompanying public key certificates, protected with a password-based
		// symmetric key -
		// Return AbstractSignatureTokenConnection signingToken

		// Return DSSPrivateKeyEntry privateKey from the PKCS12 store
		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demo[]
			// import java.awt.Color;
			// import java.awt.Font;
			// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
			// import eu.europa.esig.dss.enumerations.SignatureLevel;
			// import eu.europa.esig.dss.model.DSSDocument;
			// import eu.europa.esig.dss.model.SignatureValue;
			// import eu.europa.esig.dss.model.ToBeSigned;
			// import eu.europa.esig.dss.pades.DSSFont;
			// import eu.europa.esig.dss.pades.DSSJavaFont;
			// import eu.europa.esig.dss.pades.PAdESSignatureParameters;
			// import eu.europa.esig.dss.pades.SignatureFieldParameters;
			// import eu.europa.esig.dss.pades.SignatureImageParameters;
			// import eu.europa.esig.dss.pades.SignatureImageTextParameters;
			// import eu.europa.esig.dss.pades.signature.PAdESService;
			// import eu.europa.esig.dss.validation.CommonCertificateVerifier;

			// Preparing parameters for the PAdES signature
			PAdESSignatureParameters parameters = new PAdESSignatureParameters();
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
			// We set the digest algorithm to use with the signature algorithm. You must use the
			// same parameter when you invoke the method sign on the token. The default value is
			// SHA256
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());

			// Initialize visual signature
			SignatureImageParameters imageParameters = new SignatureImageParameters();
			// Initialize text to generate for visual signature
			// tag::font[]
			SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
			DSSFont font = new DSSJavaFont(Font.SERIF);
			font.setSize(16); // Specifies the text size value (the default font size is 12pt)
			textParameters.setFont(font);
			textParameters.setTextColor(Color.BLUE);
			textParameters.setText("My visual signature");
			imageParameters.setTextParameters(textParameters);
			// end::font[]

			// initialize signature field parameters
			SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
			fieldParameters.setOriginX(200);
			fieldParameters.setOriginY(500);
			fieldParameters.setFieldId("ExistingSignatureField");
			
			parameters.setImageParameters(imageParameters);

			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create PAdESService for signature
			PAdESService service = new PAdESService(commonCertificateVerifier);

			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// We invoke the padesService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

			// end::demo[]
			testFinalDocument(signedDocument);
		}
	}
}
