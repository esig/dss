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
package eu.europa.esig.dss.xades.extension.prettyprint;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.extension.AbstractXAdESTestExtension;
import eu.europa.esig.dss.xades.signature.XAdESService;

class XAdESDoubleLTAPrettyPrintTest extends AbstractXAdESTestExtension {

	@Override
	protected DSSDocument getSignedDocument(DSSDocument doc) {
		// Sign
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
		signatureParameters.setPrettyPrint(true);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtSignatureTime());

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}

	@Override
	protected XAdESSignatureParameters getExtensionParameters() {
		XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		extensionParameters.setPrettyPrint(true);
		return extensionParameters;
	}

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LTA;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LTA;
	}

}
