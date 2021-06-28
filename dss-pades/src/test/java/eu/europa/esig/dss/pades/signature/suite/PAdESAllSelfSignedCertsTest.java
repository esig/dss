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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PAdESAllSelfSignedCertsTest extends PKIFactoryAccess {
	
	private DSSDocument documentToSign;
	private PAdESSignatureParameters parameters;
	private PAdESService service;
	
	@BeforeEach
	public void init() {
		documentToSign = new InMemoryDocument(PAdESLevelBTest.class.getResourceAsStream("/sample.pdf"));
		
		parameters = new PAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getSelfSignedTsa());
	}

	@Test
	public void bLevelTest() {
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        DSSDocument signedDocument = sign();
        assertNotNull(signedDocument);
	}

	@Test
	public void tLevelTest() {
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        DSSDocument signedDocument = sign();
        assertNotNull(signedDocument);
	}

	@Test
	public void ltLevelTest() {
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
		Exception exception = assertThrows(IllegalInputException.class, () -> sign());
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}

	@Test
	public void ltaLevelTest() {
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		Exception exception = assertThrows(IllegalInputException.class, () -> sign());
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}
	
	private DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, parameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signDocument(documentToSign, parameters, signatureValue);
	}

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
