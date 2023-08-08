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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.signature.ExternalXAdESSignatureResult;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.xmldsig.definition.XMLDSigPaths;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.File;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelBExternalSignatureTest extends AbstractXAdESTestSignature {
	private static final Logger LOG = LoggerFactory.getLogger(XAdESLevelBExternalSignatureTest.class);
	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setSignedPropertiesCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
		signatureParameters.setSignedInfoCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
		signatureParameters.setGenerateTBSWithoutCertificate(true);

		service = new XAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected DSSDocument sign() {
		DSSDocument toBeSigned = getDocumentToSign();
		XAdESSignatureParameters params = getSignatureParameters();
		DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service = getService();

		// Generate toBeSigned without signing certificate
		assert params.getSigningCertificate() == null;
		ToBeSigned dataToSign = service.getDataToSign(getDocumentToSign(), params);

		/**
		 * Simulate an external process that (1) creates a XAdES-object which includes
		 * signing certificate (2) updates SigningInfo structure in dataToSign and
		 * (3) calculated signature value.
		 */
		ExternalXAdESSignatureResult externalSignatureResult = simulateExternalSignature(dataToSign);

		/**
		 * Construct new set of parameters including explicitly specified
		 * signed data and AdES object created by external process.
		 */
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(externalSignatureResult.getSigningDate());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignedAdESObject(externalSignatureResult.getSignedAdESObject());
		signatureParameters.setSignedData(externalSignatureResult.getSignedData());

		// Sign document using signature value created by external process.
		return service.signDocument(toBeSigned, signatureParameters, externalSignatureResult.getSignatureValue());
	}

	private ExternalXAdESSignatureResult simulateExternalSignature(ToBeSigned toBeSigned) {
		ExternalXAdESSignatureResult externalSignatureResult = new ExternalXAdESSignatureResult();

		// Get hold of signature certificate.
		externalSignatureResult.setSigningCertificate(getSigningCert());

		// Set signing date and calculate deterministic ID
		Date signingDate = new Date();
		externalSignatureResult.setSigningDate(signingDate);

		try {
			// Use Dummy XAdES builder to create XAdES object which include signing certificate, and update toBeSigned
			DummyXAdESSignatureBuilder dummyXAdESSignatureBuilder = new DummyXAdESSignatureBuilder(getSignatureParameters(), getDocumentToSign(),
					getOfflineCertificateVerifier());
			toBeSigned.setBytes(dummyXAdESSignatureBuilder.build(signingDate, getSigningCert()));
			externalSignatureResult.setSignedData(toBeSigned.getBytes());

			// Serialize XAdES object
			byte[] serializedObject = dummyXAdESSignatureBuilder.getSerializedObject();
			externalSignatureResult.setSignedAdESObject(serializedObject);

			// Calculate signature
			SignatureValue signatureValue = getToken().sign(toBeSigned, getSignatureParameters().getDigestAlgorithm(),
					getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
			assertTrue(service.isValidSignatureValue(toBeSigned, signatureValue, getSigningCert()));
			externalSignatureResult.setSignatureValue(signatureValue);
		} catch (Exception e) {
			LOG.error("Error while simulating external XAdES signature", e);
		}

		return externalSignatureResult;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	private static class DummyXAdESSignatureBuilder extends EnvelopedSignatureBuilder {

		private DummyXAdESSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument origDoc,
										   final CertificateVerifier certificateVerifier) {
			super(params, origDoc, certificateVerifier);
		}

		public byte[] build(Date signingDate, CertificateToken signingCertificate) {
			// Re-initialize parameters to simulate external process.
			params = new XAdESSignatureParameters();
			params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			params.setSignedPropertiesCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
			params.setSignedInfoCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
			params.bLevel().setSigningDate(signingDate);
			params.setSigningCertificate(signingCertificate);
			return super.build();
		}

		public byte[] getSerializedObject() {
			Element objectDom = DomUtils.getElement(signatureDom, XMLDSigPaths.OBJECT_PATH);
			return DomUtils.serializeNode(objectDom);
		}
	}

}
