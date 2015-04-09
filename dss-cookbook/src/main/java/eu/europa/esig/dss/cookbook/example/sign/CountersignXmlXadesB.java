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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.BLevelParameters.SignerLocation;
import eu.europa.esig.dss.cookbook.example.Cookbook;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * How to generate a countersignature over an existing signature
 */
public class CountersignXmlXadesB extends Cookbook {

	public static void main(final String[] args) throws IOException {

		//Select a document to countersign
		DSSDocument toCountersignDocument = new FileDocument("signedXmlXadesB.xml");

		// Create a token connection based on a pkcs12 file
		preparePKCS12TokenAndKey();

		// Preparing the parameters for the countersignature
		XAdESSignatureParameters countersigningParameters = new XAdESSignatureParameters();
		countersigningParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		countersigningParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		//The ID of the signature was manually retrieved in the document to countersign
		countersigningParameters.setToCounterSignSignatureId("id-E2727C1693F3602F89D515E6BEE5F1DC");

		//Possibility to add properties in the countersignature
		BLevelParameters blParam = countersigningParameters.bLevel();
		SignerLocation location = new SignerLocation();
		location.setCountry("Belgium");
		location.setStateOrProvince("Luxembourg");
		blParam.setSignerLocation(location);

		// Countersign the document
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(commonCertificateVerifier);
		DSSDocument countersignedDocument = service.counterSignDocument(toCountersignDocument, countersigningParameters, signingToken, privateKey);

		InputStream is = new ByteArrayInputStream(countersignedDocument.getBytes());
		DSSUtils.saveToFile(is, "target/countersigned.xml");
	}
}
