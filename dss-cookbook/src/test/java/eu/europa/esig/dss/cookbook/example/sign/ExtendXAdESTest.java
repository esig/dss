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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

/**
 * How to extend with XAdES-BASELINE signature
 *
 */
public class ExtendXAdESTest extends CookbookTools {

	@Test
	public void test() throws Exception {
		prepareXmlDoc();

		DSSDocument signedDocument = null;
		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
			parameters.setSigningCertificate(privateKey.getCertificate());
			parameters.setCertificateChain(privateKey.getCertificateChain());

			XAdESService service = new XAdESService(new CommonCertificateVerifier());
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
		}

		// tag::demoTExtend[]

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService xadesService = new XAdESService(certificateVerifier);

		// init TSP source for timestamp requesting
		xadesService.setTspSource(getOnlineTSPSource());

		DSSDocument extendedDocument = xadesService.extendDocument(signedDocument, parameters);

		// end::demoTExtend[]

		// tag::demoLTExtend[]

		parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

		certificateVerifier = new CommonCertificateVerifier();

		CommonsDataLoader commonsDataLoader = new CommonsDataLoader();

		// init revocation sources for CRL/OCSP requesting
		certificateVerifier.setCrlSource(new OnlineCRLSource(commonsDataLoader));
		certificateVerifier.setOcspSource(new OnlineOCSPSource());

		xadesService = new XAdESService(certificateVerifier);

		extendedDocument = xadesService.extendDocument(signedDocument, parameters);

		// end::demoLTExtend[]

		// tag::demoLTAExtend[]

		parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setCrlSource(new OnlineCRLSource());
		certificateVerifier.setOcspSource(new OnlineOCSPSource());

		xadesService = new XAdESService(certificateVerifier);
		xadesService.setTspSource(getOnlineTSPSource());

		extendedDocument = xadesService.extendDocument(signedDocument, parameters);

		// end::demoLTAExtend[]

		testFinalDocument(extendedDocument);
	}

}
