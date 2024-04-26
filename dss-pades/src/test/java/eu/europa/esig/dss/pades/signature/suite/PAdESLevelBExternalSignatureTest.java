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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.signature.ExternalSignatureResult;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * NOTE: This test is kept for retro-compatibility.
 * For creation of PAdES with external CMS see {@code PAdESExternalCMSSignatureBLevelTest}.
 */
public class PAdESLevelBExternalSignatureTest extends AbstractPAdESTestSignature {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBExternalSignatureTest.class);
	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(PAdESLevelBExternalSignatureTest.class.getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setGenerateTBSWithoutCertificate(true);
		signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
		signatureParameters.setSignerName(GOOD_USER);

		signingDate = new Date();
		signatureParameters.bLevel().setSigningDate(signingDate);

		service = new PAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected DSSDocument sign() {
		DSSDocument toBeSigned = getDocumentToSign();
		PAdESSignatureParameters params = getSignatureParameters();
		DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service = getService();

		// Generate toBeSigned without signing certificate
		assertNull(params.getSigningCertificate());
		ToBeSigned dataToSign = service.getDataToSign(getDocumentToSign(), params);

		// store the deterministic Id, because of different signing-certificate definition, the deterministic id may differ
		String deterministicId = signatureParameters.getContext().getDeterministicId();

		/*
		 * Simulate an external process that updates ASN.1 signed-attributes structure
		 * in dataToSign with signing certificate and calculates signature value.
		 */
		ExternalSignatureResult externalSignatureResult = simulateExternalSignature(dataToSign);

		/*
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
		signatureParameters.setSignerName(GOOD_USER);

		// ensure the same deterministic Id is used
		signatureParameters.getContext().setDeterministicId(deterministicId);

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

		SignatureValue signatureValue = getToken().sign(toBeSigned, digestAlgo, getPrivateKeyEntry());
		assertTrue(service.isValidSignatureValue(toBeSigned, signatureValue, getSigningCert()));
		externalSignatureResult.setSignatureValue(signatureValue);

		return externalSignatureResult;
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
