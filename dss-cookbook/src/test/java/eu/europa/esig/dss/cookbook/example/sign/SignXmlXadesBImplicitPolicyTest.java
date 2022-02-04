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

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * How to set implicit policy.
 */
public class SignXmlXadesBImplicitPolicyTest extends CookbookTools {

	@Test
	public void testWithImplicitPolicy() throws Exception {

		prepareXmlDoc();

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);



			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());

			// tag::demo[]

			BLevelParameters bLevelParameters = parameters.bLevel();

			Policy policy = new Policy();
			policy.setId("");

			bLevelParameters.setSignaturePolicy(policy);

			// end::demo[]

			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create xadesService for signature
			XAdESService service = new XAdESService(commonCertificateVerifier);

			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// We invoke the xadesService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);



			testFinalDocument(signedDocument);
		}
	}
}
