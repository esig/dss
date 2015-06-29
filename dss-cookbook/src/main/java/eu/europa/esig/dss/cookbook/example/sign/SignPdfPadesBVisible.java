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

import java.awt.Color;
import java.awt.Font;
import java.io.IOException;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cookbook.example.Cookbook;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

/**
 * How to sign PDF Document with PAdES-BASELINE-B and include a visual representation
 */
public class SignPdfPadesBVisible extends Cookbook {

	public static void main(final String[] args) throws IOException {
		// GET document to be signed -
		// Return DSSDocument toSignDocument
		preparePdfDoc();

		// Get a token connection based on a pkcs12 file commonly used to store private
		// keys with accompanying public key certificates, protected with a password-based
		// symmetric key -
		// Return AbstractSignatureTokenConnection signingToken

		// and it's first private key entry from the PKCS12 store
		// Return DSSPrivateKeyEntry privateKey *****
		preparePKCS12TokenAndKey();

		// Preparing parameters for the PAdES signature
		PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		// We choose the level of the signature (-B, -T, -LT, -LTA).
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		// We choose the type of the signature packaging (ENVELOPING, DETACHED).
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

		// Initialize visual signature
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		// the origin is the left and top corner of the page
		imageParameters.setxAxis(200);
		imageParameters.setyAxis(500);

		// Initialize text to generate for visual signature
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setFont(new Font("serif", Font.PLAIN, 14));
		textParameters.setTextColor(Color.BLUE);
		textParameters.setText("My visual signature");
		imageParameters.setTextParameters(textParameters);

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

		// We invoke the xadesService to sign the document with the signature value obtained in
		// the previous step.
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		// We use the DSSUtils to Save to file
		DSSUtils.saveToFile(signedDocument.openStream(), "target/signedPdfPadesBVisible.pdf");

	}
}
