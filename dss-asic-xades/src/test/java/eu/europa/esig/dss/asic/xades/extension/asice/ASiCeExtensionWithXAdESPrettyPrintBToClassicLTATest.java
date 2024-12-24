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
package eu.europa.esig.dss.asic.xades.extension.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;

class ASiCeExtensionWithXAdESPrettyPrintBToClassicLTATest extends ASiCeExtensionWithXAdESBToLTATest {

	@Override
	protected DSSDocument getSignedDocument(DSSDocument doc) {
		// Sign
		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
		signatureParameters.aSiC().setContainerType(getContainerType());
		signatureParameters.setPrettyPrint(true);

		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtSignatureTime());

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getExtensionParameters() {
		ASiCWithXAdESSignatureParameters extensionParameters = new ASiCWithXAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		extensionParameters.aSiC().setContainerType(getContainerType());
		extensionParameters.setPrettyPrint(false);
		return extensionParameters;
	}

}
