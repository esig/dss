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
package eu.europa.esig.dss.cades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.cades.CMSUtils;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

class CAdESLevelLTATS101733Test extends PKIFactoryAccess {

	@Test
	void test() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		signatureParameters.setEn319122(false);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			if (timestamp.getType().isArchivalTimestamp()) {
				++archiveTimestampCounter;
			}
		}
		assertEquals(1, archiveTimestampCounter);
		
		try (InputStream is = signedDocument.openStream()) {
			CMSSignedData cmsSignedData = new CMSSignedData(is);
			Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();
			assertEquals(1, signers.size());
			for (SignerInformation signerInformation : signers) {
				AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
				Attribute[] attributes = DSSASN1Utils.getAsn1Attributes(unsignedAttributes, OID.id_aa_ets_archiveTimestampV3);
				assertEquals(1, attributes.length);
				Attribute archiveTimestamp = attributes[0];
				
				TimeStampToken timeStampToken = CMSUtils.getTimeStampToken(archiveTimestamp);
				AttributeTable unsignedAttributes2 = timeStampToken.getUnsignedAttributes();
				Attribute[] asn1Attributes = DSSASN1Utils.getAsn1Attributes(unsignedAttributes2, OID.id_aa_ATSHashIndex);
				assertEquals(1, asn1Attributes.length);
			}
		}
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
