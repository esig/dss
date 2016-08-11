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
import java.util.Date;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cookbook.example.Cookbook;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class SigningApplication extends Cookbook {

	public static void main(String[] args) throws IOException {

		preparePKCS12TokenAndKey();

		DSSDocument toBeSigned = new FileDocument("src/main/resources/xml_example.xml");

		XAdESSignatureParameters params = new XAdESSignatureParameters();

		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(privateKey.getCertificate());
		params.setCertificateChain(privateKey.getCertificateChain());
		params.bLevel().setSigningDate(new Date());

		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(commonCertificateVerifier);
		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = signingToken.sign(dataToSign, params.getDigestAlgorithm(), privateKey);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		Utils.copy(signedDocument.openStream(), System.out);
	}
}
