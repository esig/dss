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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.IOException;
import java.util.List;

/**
 * How to sign using MS-CAPI.
 */
public class SignXmlXadesBWithMSCAPI {

	/**
	 * Main method
	 *
	 * @param args not applicable
	 * @throws Exception if an exception occurs
	 */
	public static void main(String[] args) throws DSSException, IOException {
		// GET document to be signed -
		// Return DSSDocument toSignDocument
		DSSDocument toSignDocument = new FileDocument("src/main/resources/xml_example.xml");

		// Creation of MS-CAPI signature token
		try (MSCAPISignatureToken signingToken = new MSCAPISignatureToken()) {

			List<DSSPrivateKeyEntry> list = signingToken.getKeys();
			// Choose the right private key entry from store.
			// The index will depend of the number of the certificates on your card.
			System.out.println(list.size());
			DSSPrivateKeyEntry privateKey = list.get(0);

			// Preparing parameters for the PAdES signature
			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			// We choose the type of the signature packaging (ENVELOPING, DETACHED).
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			// We set the digest algorithm to use with the signature algorithm. You must use the
			// same parameter when you invoke the method sign on the token.
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());

			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create CAdES xadesService for signature
			XAdESService xadesService = new XAdESService(commonCertificateVerifier);

			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = xadesService.getDataToSign(toSignDocument, parameters);

			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// We invoke the xadesService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = xadesService.signDocument(toSignDocument, parameters, signatureValue);

			// save the signed document on the filesystem
			signedDocument.save("target/signedXmlXadesMSCapi.xml");
		}
	}
}
