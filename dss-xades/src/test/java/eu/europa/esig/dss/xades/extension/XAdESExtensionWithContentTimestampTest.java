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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.RepeatedTest;

import java.io.File;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESExtensionWithContentTimestampTest extends PKIFactoryAccess {
	
	@RepeatedTest(10)
	void test() {
		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		
		Date oneDayBefore = getDateWithHoursDifference(-24);
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(oneDayBefore);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		
		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());
		XAdESService service = new XAdESService(certificateVerifier);
        service.setTspSource(getGoodTsaByTime(oneDayBefore));
		
		TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);

		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));

		signatureParameters.bLevel().setSigningDate(getDateWithHoursDifference(24));
		service.setTspSource(getAlternateGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		Exception exception = assertThrows(AlertException.class, () -> service.extendDocument(signedDocument, signatureParameters));
		assertTrue(exception.getMessage().contains("Fresh revocation data is missing for one or more certificate(s)."));
		
	}
	
	private Date getDateWithHoursDifference(int hours) {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.HOUR, hours);
		return cal.getTime();
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
