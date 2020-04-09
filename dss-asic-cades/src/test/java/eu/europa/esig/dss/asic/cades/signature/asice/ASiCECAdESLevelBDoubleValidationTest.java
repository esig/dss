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
package eu.europa.esig.dss.asic.cades.signature.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ASiCECAdESLevelBDoubleValidationTest extends PKIFactoryAccess {
	
	@Test
	public void test() throws Exception {
		List<DSSDocument> documentToSigns = new ArrayList<>();
		documentToSigns.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT));
		documentToSigns.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));
	
		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		
		ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSigns, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSigns, signatureParameters, signatureValue);

		// use complete certificate verifier, because the revocation data has to be obtained
		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		Date valdiationTime = new Date();
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(certificateVerifier);
		validator.setValidationTime(valdiationTime);
		
		Reports reportsOne = validator.validateDocument();
		
		validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(certificateVerifier);
		validator.setValidationTime(valdiationTime);
		
		Reports reportsTwo = validator.validateDocument();
		
		assertEquals(reportsOne.getSimpleReport().getIndication(reportsOne.getSimpleReport().getFirstSignatureId()), 
				reportsTwo.getSimpleReport().getIndication(reportsTwo.getSimpleReport().getFirstSignatureId()));
		
		if (reportsOne.getSimpleReport().getSubIndication(reportsOne.getSimpleReport().getFirstSignatureId()) == null) {
			assertNull(reportsTwo.getSimpleReport().getSubIndication(reportsTwo.getSimpleReport().getFirstSignatureId()));
		} else {
			assertEquals(reportsOne.getSimpleReport().getSubIndication(reportsOne.getSimpleReport().getFirstSignatureId()), 
					reportsTwo.getSimpleReport().getSubIndication(reportsTwo.getSimpleReport().getFirstSignatureId()));
		}
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
