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
import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cookbook.example.Cookbook;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * How to add signed properties to the signature.
 */
public class signXmlXadesBProperties extends Cookbook {

	public static void main(String[] args) throws DSSException, IOException {

		prepareXmlDoc();

		preparePKCS12TokenAndKey();

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

		BLevelParameters bLevelParameters = parameters.bLevel();
		bLevelParameters.addClaimedSignerRole("My Claimed Role");

		BLevelParameters.SignerLocation signerLocation = new BLevelParameters.SignerLocation();
		signerLocation.setCountry("Belgium");
		signerLocation.setStateOrProvince("Luxembourg");
		signerLocation.setPostalCode("1234");
		signerLocation.setCity("SimCity");
		bLevelParameters.setSignerLocation(signerLocation);

		List<String> commitmentTypeIndications = new ArrayList<String>();
		commitmentTypeIndications.add("http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin");
		commitmentTypeIndications.add("http://uri.etsi.org/01903/v1.2.2#ProofOfApproval");
		bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(verifier);
		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
		SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		DSSUtils.saveToFile(signedDocument.openStream(), "target/signedXmlXadesBProperties.xml");
	}
}
