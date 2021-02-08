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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.UUID;

import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.extension.AbstractTestExtension;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public abstract class AbstractXAdESTestExtension extends AbstractTestExtension<XAdESSignatureParameters, XAdESTimestampParameters> {

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getGoodTsa();
	}

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getAlternateGoodTsa();
	}

	@Override
	protected FileDocument getOriginalDocument() {
		File originalDoc = new File("target/original-" + UUID.randomUUID().toString() + ".xml");
		try (FileOutputStream fos = new FileOutputStream(originalDoc); FileInputStream fis = new FileInputStream(new File("src/test/resources/sample.xml"))) {
			Utils.copy(fis, fos);
		} catch (IOException e) {
			throw new DSSException("Unable to create the original document", e);
		}
		return new FileDocument(originalDoc);
	}

	@Override
	protected DSSDocument getSignedDocument(DSSDocument doc) {
		// Sign
		XAdESSignatureParameters signatureParameters = getSignatureParameters();
		XAdESService service = getSignatureServiceToSign();

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}

	protected XAdESSignatureParameters getSignatureParameters() {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
		return signatureParameters;
	}

	@Override
	protected XAdESService getSignatureServiceToSign() {
		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtSignatureTime());
		return service;
	}

	@Override
	protected XAdESService getSignatureServiceToExtend() {
		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtExtensionTime());
		return service;
	}

	@Override
	protected XAdESSignatureParameters getExtensionParameters() {
		XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		return extensionParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
