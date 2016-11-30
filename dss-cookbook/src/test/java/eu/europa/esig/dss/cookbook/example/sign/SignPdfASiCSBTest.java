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

import java.io.IOException;

import org.junit.Test;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

/**
 * How to sign with ASiC_S_BASELINE_B
 */
public class SignPdfASiCSBTest extends CookbookTools {

	@Test
	public void signASiCSBaselineB() throws IOException {

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

		// tag::demo[]

		// Preparing parameters for the AsicS signature
		ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
		// We choose the level of the signature (-B, -T, -LT, LTA).
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		// We choose the container type (ASiC-S or ASiC-E)
		parameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		// We set the digest algorithm to use with the signature algorithm. You must use the
		// same parameter when you invoke the method sign on the token. The default value is
		// SHA256
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		// We set the signing certificate
		parameters.setSigningCertificate(privateKey.getCertificate());
		// We set the certificate chain
		parameters.setCertificateChain(privateKey.getCertificateChain());

		// Create common certificate verifier
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		// Create ASiC service for signature
		ASiCWithXAdESService service = new ASiCWithXAdESService(commonCertificateVerifier);

		// Get the SignedInfo segment that need to be signed.
		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

		// This function obtains the signature value for signed information using the
		// private key and specified algorithm
		DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

		// We invoke the xadesService to sign the document with the signature value obtained in
		// the previous step.
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		// end::demo[]

		testFinalDocument(signedDocument);
	}
}
