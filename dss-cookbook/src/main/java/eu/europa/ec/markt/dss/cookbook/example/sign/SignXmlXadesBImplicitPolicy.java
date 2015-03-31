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
package eu.europa.ec.markt.dss.cookbook.example.sign;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.XAdESSignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

/**
 * How to set implicit policy.
 */
public class SignXmlXadesBImplicitPolicy extends Cookbook {

	public static void main(String[] args) throws IOException {

		prepareXmlDoc();

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		BLevelParameters bLevelParameters = parameters.bLevel();

		BLevelParameters.Policy policy = new BLevelParameters.Policy();
		policy.setId("");

		bLevelParameters.setSignaturePolicy(policy);

		// Create common certificate verifier
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		// Create xadesService for signature
		XAdESService service = new XAdESService(commonCertificateVerifier);

		// Get the SignedInfo segment that need to be signed.
		byte[] dataToSign = service.getDataToSign(toSignDocument, parameters);

		// This function obtains the signature value for signed information using the
		// private key and specified algorithm
		DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

		// We invoke the xadesService to sign the document with the signature value obtained in
		// the previous step.
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		InputStream is = new ByteArrayInputStream(signedDocument.getBytes());
		DSSUtils.saveToFile(is, "target/signedXmlXadesBImplicitPolicy.xml");
	}
}
