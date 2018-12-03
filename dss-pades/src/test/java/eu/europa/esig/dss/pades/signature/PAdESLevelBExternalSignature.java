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
package eu.europa.esig.dss.pades.signature;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.ExternalSignatureResult;
import eu.europa.esig.dss.x509.CertificateToken;

public class PAdESLevelBExternalSignature extends AbstractPkiFactoryTestDocumentSignatureService<PAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBExternalSignature.class);
	private DocumentSignatureService<PAdESSignatureParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private Date signingDate;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(PAdESLevelBExternalSignature.class.getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setGenerateTBSWithoutCertificate(true);
		signatureParameters.setSignatureName(GOOD_USER);

		signingDate = new Date();
		signatureParameters.bLevel().setSigningDate(signingDate);

		service = new PAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected DSSDocument sign() {
		DSSDocument toBeSigned = getDocumentToSign();
		PAdESSignatureParameters params = getSignatureParameters();
		DocumentSignatureService<PAdESSignatureParameters> service = getService();

		// Generate toBeSigned without signing certificate
		assert params.getSigningCertificate() == null;
		ToBeSigned dataToSign = service.getDataToSign(getDocumentToSign(), params);

		/**
		 * Simulate an external process that updates ASN.1 signed-attributes structure
		 * in dataToSign with signing certificate and calculates signature value.
		 */
		ExternalSignatureResult externalSignatureResult = simulateExternalSignature(dataToSign);

		/**
		 * Construct new set of parameters including explicitly specified signed data
		 * created by external process and signature name used when calculating toBeSigned.
		 */
		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignedData(externalSignatureResult.getSignedData());
		signatureParameters.setSignatureName(GOOD_USER);

		// Sign document using signature value created by external process.
		return service.signDocument(toBeSigned, signatureParameters, externalSignatureResult.getSignatureValue());
	}

	private ExternalSignatureResult simulateExternalSignature(ToBeSigned toBeSigned) {
		ExternalSignatureResult externalSignatureResult = new ExternalSignatureResult();

		// Get hold of signature certificate.
		CertificateToken signingCertificate = getSigningCert();
		externalSignatureResult.setSigningCertificate(signingCertificate);

		DigestAlgorithm digestAlgo = signatureParameters.getDigestAlgorithm();

		// Add the signing-certificate/signing-certificate-v2 attribute to DER encoded SignedAttributes.
		try (ASN1InputStream asn1InputStream = new ASN1InputStream(toBeSigned.getBytes())) {
			DLSet dlSet = (DLSet) asn1InputStream.readObject();
			AttributeTable signedAttribute = new AttributeTable(dlSet);
			ASN1EncodableVector signedAttributeEncodableVector = signedAttribute.toASN1EncodableVector();

			CMSUtils.addSigningCertificateAttribute(signedAttributeEncodableVector, digestAlgo, signingCertificate);

			DERSet signedAttributesData = new DERSet(signedAttributeEncodableVector);

			// Update toBeSigned
			toBeSigned.setBytes(signedAttributesData.getEncoded());
			externalSignatureResult.setSignedData(toBeSigned.getBytes());
		} catch (Exception e) {
			LOG.error("Error while simulating external PAdES signature", e);
		}

		SignatureValue signatureValue = getToken().sign(toBeSigned, digestAlgo, getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
		externalSignatureResult.setSignatureValue(signatureValue);

		return externalSignatureResult;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.PDF;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}
}
