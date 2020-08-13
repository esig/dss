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

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

/**
 * How to sign PDF Document with PAdES-BASELINE-B
 */
public class SignPdfPadesBTest extends CookbookTools {

	@Test
	public void signPAdESBaselineB() throws Exception {

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

			// Optionally or for debug purpose :
			// Validate the signature value against the original dataToSign
			assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, privateKey.getCertificate()));

			// We invoke the xadesService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

			// end::demo[]

			// tag::policy[]
			// Instantiate a Policy object
			Policy signaturePolicy = new Policy();
			// The string representation of the OID of the signature policy to use when signing.
			signaturePolicy.setId("1.2.3.4.5.6");
			// Defines a policy identifier qualifier
			signaturePolicy.setQualifier(ObjectIdentifierQualifier.OID_AS_URN);
			// Defines a description for a signature policy
			signaturePolicy.setDescription("Perfect Signature Policy");
			// The hash function used to compute the value of the SignaturePolicyHashValue entry. 
			// Entries must be represented the same way as in table 257 of ISO 32000-1 (cf. <<R05>>).
			signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA1);
			// The value of the hash of the signature policy, computed the same way as 
			// in clause 5.2.9 of CAdES (ETSI EN 319 122 (cf. <<R02>>)).
			signaturePolicy.setDigestValue(new byte[] { 'd', 'i', 'g', 'e', 's', 't', 'v', 'a', 'l', 'u', 'e' });
			// Defines a URI where the policy can be accessed from
			signaturePolicy.setSpuri("http://spuri.test");
			parameters.bLevel().setSignaturePolicy(signaturePolicy);
			// end::policy[]

			testFinalDocument(signedDocument);
		}
	}
}
