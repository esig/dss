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
package eu.europa.esig.dss.asic.extension;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.extension.AbstractTestExtension;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public abstract class AbstractTestASiCwithXAdESExtension extends AbstractTestExtension<ASiCWithXAdESSignatureParameters> {

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry entryUserA = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		DSSDocument document = new InMemoryDocument("Hello world!".getBytes(), "test.bin");

		// Sign
		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.setSigningCertificate(entryUserA.getCertificate());
		signatureParameters.setCertificateChain(entryUserA.getCertificateChain());
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
		signatureParameters.aSiC().setContainerType(getContainerType());

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier);
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1)));

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = sign(signatureParameters.getSignatureAlgorithm(), entryUserA, dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);
		return signedDocument;
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getExtensionParameters() {
		ASiCWithXAdESSignatureParameters extensionParameters = new ASiCWithXAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		extensionParameters.aSiC().setContainerType(getContainerType());
		return extensionParameters;
	}

	protected abstract ASiCContainerType getContainerType();

	@Override
	protected DocumentSignatureService<ASiCWithXAdESSignatureParameters> getSignatureServiceToExtend() throws Exception {
		ASiCWithXAdESService service = new ASiCWithXAdESService(new CommonCertificateVerifier());
		CertificateService certificateService = new CertificateService();
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1)));
		return service;
	}

}
