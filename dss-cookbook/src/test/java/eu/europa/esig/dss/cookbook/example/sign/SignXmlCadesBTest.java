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

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

/**
 * How to sign with CAdES-BASELINE-B enveloping signature.
 */
public class SignXmlCadesBTest extends CookbookTools {

	@Test
	public void signCAdESBaselineB() throws Exception {

		// GET document to be signed -
		// Return DSSDocument toSignDocument
		prepareXmlDoc();

		// Get a token connection based on a pkcs12 file commonly used to store private
		// keys with accompanying public key certificates, protected with a password-based
		// symmetric key -
		// Return AbstractSignatureTokenConnection signingToken

		// and it's first private key entry from the PKCS12 store
		// Return DSSPrivateKeyEntry privateKey *****
		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demo[]

			// Preparing parameters for the CAdES signature
			CAdESSignatureParameters parameters = new CAdESSignatureParameters();
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
			// We choose the type of the signature packaging (ENVELOPING, DETACHED).
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
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
			// Create CAdESService for signature
			CAdESService service = new CAdESService(commonCertificateVerifier);

			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// We invoke the CAdESService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

			// end::demo[]

			testFinalDocument(signedDocument);
		}
	}
}
