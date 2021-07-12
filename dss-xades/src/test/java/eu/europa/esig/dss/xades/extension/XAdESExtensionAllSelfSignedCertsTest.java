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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class XAdESExtensionAllSelfSignedCertsTest extends PKIFactoryAccess {
	
	private DSSDocument documentToSign;
	private XAdESSignatureParameters parameters;
	private XAdESService service;
	
	@BeforeEach
	public void init() {
		documentToSign = new FileDocument("src/test/resources/sample.xml");
		
		parameters = new XAdESSignatureParameters();
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getSelfSignedTsa());
	}

	@Test
	public void bToTTest() {
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        DSSDocument signedDocument = sign();
        
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		DSSDocument extendedDocument = extend(signedDocument);
		assertNotNull(extendedDocument);
	}

	@Test
	public void bToLTTest() {
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		DSSDocument signedDocument = sign();

		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		Exception exception = assertThrows(IllegalInputException.class, () -> extend(signedDocument));
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}

	@Test
	public void tToLTTest() {
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		DSSDocument signedDocument = sign();

		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		Exception exception = assertThrows(IllegalInputException.class, () -> extend(signedDocument));
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}

	@Test
	public void tToLTATest() {
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		DSSDocument signedDocument = sign();

		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		Exception exception = assertThrows(IllegalInputException.class, () -> extend(signedDocument));
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}
	
	private DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, parameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signDocument(documentToSign, parameters, signatureValue);
	}
	
	private DSSDocument extend(DSSDocument document) {
		return service.extendDocument(document, parameters);
	}

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
