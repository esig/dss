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
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.parameter.TimestampParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.timestamp.TimestampService;
import eu.europa.ec.markt.dss.signature.validation.TimestampToken;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.TimestampType;

/**
 * Shows how to generate an AllDataObjectsTimestamp
 */

public class SignXmlXadesBAllDataObjectsTimestamp extends Cookbook {

	public static void main(String[] args) throws IOException {
		//Select document that will eventually be signed
		prepareXmlDoc();

		//Set signature token
		preparePKCS12TokenAndKey();

		//Define the references that have to be considered for the AllDataObjectsTimestamp
		List<DSSReference> references = new ArrayList<DSSReference>();
		DSSReference dssReference = new DSSReference();
		dssReference.setContents(toSignDocument);
		dssReference.setUri(dssReference.getContents().getName());
		dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA1);
		references.add(dssReference);

		//Define the signature parameters
		SignatureParameters signatureParameters = new SignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setReferences(references);
		signatureParameters.setPrivateKeyEntry(signingToken.getKeys().get(0));
		signatureParameters.setSigningToken(signingToken);

		TimestampParameters contentTimestampParameters = new TimestampParameters();
		contentTimestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
		contentTimestampParameters.setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
		signatureParameters.setContentTimestampParameters(contentTimestampParameters);

		//Define the contentTimestamp specific parameters
		TimestampService timestampService = new TimestampService(getMockTSPSource(), new CertificatePool());
		TimestampToken timestampToken = timestampService.generateXAdESContentTimestampAsTimestampToken(toSignDocument, signatureParameters,
				TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);

		//The AllDataObjectsTimestamp has been generated, now we have to include it in the signature parameters
		List<TimestampToken> contentTimestamps = new ArrayList<TimestampToken>();
		contentTimestamps.add(timestampToken);
		signatureParameters.setContentTimestamps(contentTimestamps);

		//Create the signature, including the AllDataObjectsTimestamp
		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(verifier);
		DSSDocument signedDocument = service.signDocument(toSignDocument, signatureParameters);

		InputStream is = new ByteArrayInputStream(signedDocument.getBytes());

		DSSUtils.saveToFile(is, "target/signedXmlXadesBAllDataObjectsTimestamp.xml");
	}
}
