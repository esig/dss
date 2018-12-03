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
package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.fail;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.PKIFactoryAccess;

public class PAdESLevelBNotEnoughSpaceForSignature extends PKIFactoryAccess {

	@Test
	public void testException() throws Exception {
		DSSDocument toBeSigned = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setSignatureSize(2); // 2 bytes

		DocumentSignatureService<PAdESSignatureParameters> service = new PAdESService(getCompleteCertificateVerifier());

		try {
			ToBeSigned dataToSign = service.getDataToSign(toBeSigned, signatureParameters);
			SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
			service.signDocument(toBeSigned, signatureParameters, signatureValue);
			fail("Not enough space");
		} catch (DSSException e) {
			// assertTrue(ExceptionUtils.getStackTrace(e).contains("not enough space"));
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
