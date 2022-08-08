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

import eu.europa.esig.dss.asic.common.SecureContainerHandler;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

/**
 * How to sign with ASiC_S_BASELINE_B
 */
public class SignOneFileWithASiCSBTest extends CookbookTools {

	@Test
	public void signASiCSBaselineB() throws Exception {

		// GET document to be signed -
		// Return DSSDocument toSignDocument
		preparePdfDoc();

		// Get a token connection based on a pkcs12 file commonly used to store private
		// keys with accompanying public key certificates, protected with a password-based
		// symmetric key -
		// Return SignatureTokenConnection signingToken

		// and it's first private key entry from the PKCS12 store
		// Return DSSPrivateKeyEntry privateKey *****
		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demo[]
			// import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
			// import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
			// import eu.europa.esig.dss.enumerations.ASiCContainerType;
			// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
			// import eu.europa.esig.dss.enumerations.SignatureLevel;
			// import eu.europa.esig.dss.model.DSSDocument;
			// import eu.europa.esig.dss.model.SignatureValue;
			// import eu.europa.esig.dss.model.ToBeSigned;
			// import eu.europa.esig.dss.validation.CommonCertificateVerifier;

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

			// tag::zipUtils[]
			// import eu.europa.esig.dss.asic.common.SecureContainerHandler;
			// import eu.europa.esig.dss.asic.common.ZipUtils;

			// Instantiate a SecureContainerHandler in order to configure ZIP securities
			SecureContainerHandler secureContainerHandler = new SecureContainerHandler();

			// Sets the maximum allowed number of files within an archive. (Default : 1000)
			// If the number exceeds, an exception will be thrown.
			secureContainerHandler.setMaxAllowedFilesAmount(1000);

			// Sets the maximum allowed number of malformed/corrupted files within an archive. (Default : 100)
			// If the number exceeds, an exception will be thrown.
			secureContainerHandler.setMaxMalformedFiles(100);

			// Sets a maximum allowed ratio of decompressed data to compressed data within an archive.
			// This check allows z ZIP-bomb detection. (Default : 100)
			// If the number exceeds, an exception will be thrown.
			secureContainerHandler.setMaxCompressionRatio(100);

			// Sets the maximum size of uncompressed data, exceeding which aforementioned security check is enforced.
			// Default : 1000000 (1MB).
			// NOTE : ZIP-bomb check can be not necessary for very small documents,
			// as it still should not cause memory overhead.
			secureContainerHandler.setThreshold(1000000);

			// As a limitation of JDK, when reading an archive from memory (e.g. using `InMemoryDocument`),
			// it is not possible to read comments from a ZIP entry of an archive.
			// However, the comments still can be obtained using `java.util.zip.ZipFile` class when working
			// with a document from filesystem (i.e. with a `FileDocument`).
			// When this property is set to `true`, a new stream will be open to the file,
			// to extract comments associated with the container's entries.
			// Default : false (do not read comments)
			secureContainerHandler.setExtractComments(true);

			// As a singleton, the provided handler will be used across the whole DSS code.
			ZipUtils.getInstance().setZipContainerHandler(secureContainerHandler);

			// end::zipUtils[]

			testFinalDocument(signedDocument);
		}
	}
}
