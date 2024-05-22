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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSXAdESAllSelfSignedCertsTest extends AbstractASiCSXAdESTestSignature {
	
	private DSSDocument documentToSign;
	private ASiCWithXAdESSignatureParameters parameters;
	private ASiCWithXAdESService service;
	private CertificateVerifier certificateVerifier;
	
	@BeforeEach
	public void init() {
		documentToSign = new InMemoryDocument("Hello World!".getBytes());
		
		parameters = new ASiCWithXAdESSignatureParameters();
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		parameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		certificateVerifier = getCompleteCertificateVerifier();
		service = new ASiCWithXAdESService(certificateVerifier);
        service.setTspSource(getSelfSignedTsa());
	}

	@Test
	public void bLevelTest() {
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        DSSDocument signedDocument = sign();
        assertNotNull(signedDocument);
	}

	@Test
	public void tLevelTest() {
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
        DSSDocument signedDocument = sign();
        assertNotNull(signedDocument);
	}

	@Test
	public void ltLevelTest() {
		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		Exception exception = assertThrows(AlertException.class, () -> super.signAndVerify());
		assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument signedDocument = sign();
		assertNotNull(signedDocument);
	}

	@Test
	public void ltaLevelTest() {
		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		Exception exception = assertThrows(AlertException.class, () -> super.signAndVerify());
		assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument signedDocument = sign();
		assertNotNull(signedDocument);
	}

	@Test
	public void cLevelTest() {
		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		parameters.setSignatureLevel(SignatureLevel.XAdES_C);
		Exception exception = assertThrows(AlertException.class, () -> super.signAndVerify());
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument signedDocument = sign();
		assertNotNull(signedDocument);
	}

	@Test
	public void xLevelTest() {
		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		parameters.setSignatureLevel(SignatureLevel.XAdES_X);
		Exception exception = assertThrows(AlertException.class, () -> super.signAndVerify());
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument signedDocument = sign();
		assertNotNull(signedDocument);
	}

	@Test
	public void xlLevelTest() {
		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		parameters.setSignatureLevel(SignatureLevel.XAdES_XL);
		Exception exception = assertThrows(AlertException.class, () -> super.signAndVerify());
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument signedDocument = sign();
		assertNotNull(signedDocument);
	}

	@Test
	public void aLevelTest() {
		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		parameters.setSignatureLevel(SignatureLevel.XAdES_A);
		Exception exception = assertThrows(AlertException.class, () -> super.signAndVerify());
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument signedDocument = sign();
		assertNotNull(signedDocument);
	}

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	public ASiCWithXAdESService getService() {
		return service;
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
		return parameters;
	}

	@Override
	public void signAndVerify() {
		// do nothing
	}

}
