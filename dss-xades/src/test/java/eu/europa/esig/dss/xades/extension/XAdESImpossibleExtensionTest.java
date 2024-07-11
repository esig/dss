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
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XAdESImpossibleExtensionTest extends PKIFactoryAccess {

	@Test
	void xmldsig() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/xmldsig-only.xml");

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		Exception exception = assertThrows(IllegalInputException.class, () -> service.extendDocument(doc, parameters));
		assertEquals("Signing-certificate token was not found! Unable to verify its validity range. " +
						"Provide signing-certificate or use method #setGenerateTBSWithoutCertificate(true) " +
						"for signature creation without signing-certificate.",
				exception.getMessage());

		parameters.setGenerateTBSWithoutCertificate(true);
		parameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);

		exception = assertThrows(IllegalInputException.class, () -> service.extendDocument(doc, parameters));
		assertEquals("The signature does not contain QualifyingProperties element (or contains more than one)! Extension is not possible.",
				exception.getMessage());
	}

	@Test
	void notSigned() {
		DSSDocument doc = new FileDocument("src/test/resources/sample.xml");

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		Exception exception = assertThrows(IllegalInputException.class, () -> service.extendDocument(doc, parameters));
		assertEquals("There is no signature to extend!", exception.getMessage());
	}
	
	@Test
	void digestDocumentWithLTALevelTest() {
		DSSDocument doc = new FileDocument("src/test/resources/sample.xml");
		DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA512, Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA512, doc)));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		
		ToBeSigned dataToSign = service.getDataToSign(digestDocument, parameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(doc, parameters, signatureValue);

		XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
		extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		extensionParameters.setDetachedContents(Collections.singletonList(digestDocument));

		Exception exception = assertThrows(IllegalArgumentException.class, () -> service.extendDocument(signedDocument, extensionParameters));
		assertEquals("XAdES-LTA requires complete binaries of signed documents! Extension with a DigestDocument is not possible.", exception.getMessage());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
