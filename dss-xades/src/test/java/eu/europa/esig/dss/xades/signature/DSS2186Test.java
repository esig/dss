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
package eu.europa.esig.dss.xades.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

class DSS2186Test extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		DSSDocument document = new FileDocument("src/test/resources/sample.xml");
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		
		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		TimestampToken contentTimestamp = service.getContentTimestamp(document, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));

		ToBeSigned toBeSigned = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(toBeSigned, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDoc = service.signDocument(document, signatureParameters, signatureValue);

		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

		contentTimestamp = service.getContentTimestamp(signedDoc, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));

		toBeSigned = service.getDataToSign(signedDoc, signatureParameters);
		signatureValue = getToken().sign(toBeSigned, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedTwiceDoc = service.signDocument(signedDoc, signatureParameters, signatureValue);
		assertNotNull(signedTwiceDoc);
		
		return signedTwiceDoc;
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(4, timestampList.size());

		List<TimestampWrapper> signatureTsts = new ArrayList<>();
		List<TimestampWrapper> contentTsts = new ArrayList<>();
		for (TimestampWrapper timestampWrapper : timestampList) {
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			
			if (timestampWrapper.getType().isSignatureTimestamp()) {
				signatureTsts.add(timestampWrapper);
			} else if (timestampWrapper.getType().isContentTimestamp()) {
				contentTsts.add(timestampWrapper);
			}
		}
		assertEquals(2, signatureTsts.size());
		assertEquals(2, contentTsts.size());
		
		assertEquals(contentTsts.get(0).getMessageImprint().getDigestMethod(), contentTsts.get(1).getMessageImprint().getDigestMethod());
		assertArrayEquals(contentTsts.get(0).getMessageImprint().getDigestValue(), contentTsts.get(1).getMessageImprint().getDigestValue());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
