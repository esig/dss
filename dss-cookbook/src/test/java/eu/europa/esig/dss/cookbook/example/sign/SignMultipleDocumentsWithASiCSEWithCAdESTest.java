/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

class SignMultipleDocumentsWithASiCSEWithCAdESTest extends CookbookTools {

	@Test
	void signASiCEBaselineB() throws Exception {

		// Get a token connection based on a pkcs12 file commonly used to store
		// private
		// keys with accompanying public key certificates, protected with a
		// password-based
		// symmetric key -
		// Return AbstractSignatureTokenConnection signingToken

		// and it's first private key entry from the PKCS12 store
		// Return DSSPrivateKeyEntry privateKey *****
		try (SignatureTokenConnection signingToken = getPkcs12Token()) {
			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demo[]
			// import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
			// import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
			// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
			// import eu.europa.esig.dss.model.DSSDocument;
			// import eu.europa.esig.dss.model.SignatureValue;
			// import eu.europa.esig.dss.model.ToBeSigned;
			// import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
			// import java.util.List;

			// Preparing the documents to be embedded in the container and signed
			List<DSSDocument> documentsToBeSigned = new ArrayList<>();
			documentsToBeSigned.add(new FileDocument("src/main/resources/hello-world.pdf"));
			documentsToBeSigned.add(new FileDocument("src/main/resources/xml_example.xml"));

			// Preparing parameters for the ASiC-E signature
			ASiCWithCAdESSignatureParameters parameters = new ASiCWithCAdESSignatureParameters();

			// We choose the level of the signature (-B, -T, -LT or -LTA).
			parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
			// We choose the container type (ASiC-S pr ASiC-E)
			parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

			// We set the digest algorithm to use with the signature algorithm. You
			// must use the
			// same parameter when you invoke the method sign on the token. The
			// default value is
			// SHA256
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());

			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create ASiC service for signature
			ASiCWithCAdESService service = new ASiCWithCAdESService(commonCertificateVerifier);

			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(documentsToBeSigned, parameters);

			// This function obtains the signature value for signed information
			// using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// We invoke the xadesService to sign the document with the signature
			// value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(documentsToBeSigned, parameters, signatureValue);

			// end::demo[]

			testFinalDocument(signedDocument);
		}
	}

}
