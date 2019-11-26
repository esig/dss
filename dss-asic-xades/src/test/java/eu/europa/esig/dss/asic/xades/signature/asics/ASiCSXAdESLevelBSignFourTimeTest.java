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
package eu.europa.esig.dss.asic.xades.signature.asics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * @author axel.abinet
 *
 */
public class ASiCSXAdESLevelBSignFourTimeTest extends PKIFactoryAccess {

	@Test
	public void test() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");

		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

		dataToSign = service.getDataToSign(signedDocument, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument resignedDocument = service.signDocument(signedDocument, signatureParameters, signatureValue);

		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

		dataToSign = service.getDataToSign(resignedDocument, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		resignedDocument = service.signDocument(resignedDocument, signatureParameters, signatureValue);

		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

		dataToSign = service.getDataToSign(resignedDocument, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		resignedDocument = service.signDocument(resignedDocument, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(resignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(4, signatureIdList.size());
		for (String sigId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(sigId));
			assertNotEquals(Indication.FAILED, reports.getSimpleReport().getIndication(sigId));
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
