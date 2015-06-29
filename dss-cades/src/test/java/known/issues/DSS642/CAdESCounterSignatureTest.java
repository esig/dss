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
package known.issues.DSS642;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockSignatureTokenConnection;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;

public class CAdESCounterSignatureTest {

	private static final Logger logger = LoggerFactory.getLogger(CAdESCounterSignatureTest.class);

	@Test
	public void test() throws Exception {
		CertificateService certificateService = new CertificateService();
		final MockPrivateKeyEntry entryUserA = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);
		final MockPrivateKeyEntry entryUserB = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		DSSDocument document = new FileDocument(new File("src/test/resources/sample.xml"));

		// Sign
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(entryUserA.getCertificate());
		signatureParameters.setCertificateChain(entryUserA.getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = sign(signatureParameters.getSignatureAlgorithm(), entryUserA, dataToSign);
		DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		// Countersign

		final InputStream inputStream = signedDocument.openStream();
		final CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
		IOUtils.closeQuietly(inputStream);

		SignerInformationStore signerInfosStore = cmsSignedData.getSignerInfos();

		Collection<SignerInformation> signerInfos = signerInfosStore.getSigners();
		assertEquals(1, signerInfos.size());
		SignerInformation signerInfo = signerInfos.iterator().next();

		Thread.sleep(1000);

		CAdESSignatureParameters countersigningParameters = new CAdESSignatureParameters();
		countersigningParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		countersigningParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		countersigningParameters.setSigningCertificate(entryUserB.getCertificate());
		countersigningParameters.setCertificateChain(entryUserB.getCertificateChain());

		DSSDocument counterSignDocument = service.counterSignDocument(signedDocument, countersigningParameters, signerInfo.getSID(), new MockSignatureTokenConnection(), entryUserB);
		assertNotNull(counterSignDocument);

		counterSignDocument.save("target/countersign.p7m");

		CMSSignedData data = new CMSSignedData(counterSignDocument.openStream());

		SignerInformationStore informationStore = data.getSignerInfos();
		Collection<SignerInformation> signers = informationStore.getSigners();
		for (SignerInformation signerInformation : signers) {
			AttributeTable signedAttributes = signerInformation.getSignedAttributes();
			Attribute attribute = signedAttributes.get(PKCSObjectIdentifiers.pkcs_9_at_contentType);
			assertNotNull(attribute);
			SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
			assertNotNull(counterSignatures);
			Collection<SignerInformation> signersCounter = counterSignatures.getSigners();
			for (SignerInformation signerCounter : signersCounter) {
				AttributeTable signedAttributes2 = signerCounter.getSignedAttributes();
				Attribute attribute2 = signedAttributes2.get(PKCSObjectIdentifiers.pkcs_9_at_contentType); // Counter-signatures don't allow content-type
				assertNull(attribute2);
			}
		}

		SignerInformationVerifierProvider vProv = new SignerInformationVerifierProvider() {
			@Override
			public SignerInformationVerifier get(SignerId signerId) throws OperatorCreationException {
				if (entryUserA.getCertificate().getSerialNumber().equals(signerId.getSerialNumber())) {
					return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
							entryUserA.getCertificate().getCertificate());
				} else if (entryUserB.getCertificate().getSerialNumber().equals(signerId.getSerialNumber())) {
					return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
							entryUserB.getCertificate().getCertificate());
				} else {
					throw new IllegalStateException("no signerID matched");
				}
			}
		};

		// Validate both signatures by BC
		assertTrue(data.verifySignatures(vProv, false));

		// Validate
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(counterSignDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");
		assertEquals(2, signatures.size());

		boolean foundCounterSignature = false;
		for (XmlDom xmlDom : signatures) {
			String type = xmlDom.getAttribute("Type");
			if (AttributeValue.COUNTERSIGNATURE.equals(type)) {
				foundCounterSignature = true;
			}
			assertTrue(diagnosticData.isBLevelTechnicallyValid(xmlDom.getAttribute("Id")));
		}
		assertTrue(foundCounterSignature);
	}

	private SignatureValue sign(SignatureAlgorithm algo, MockPrivateKeyEntry privateKey, ToBeSigned bytesToSign) throws GeneralSecurityException {
		return TestUtils.sign(algo, privateKey, bytesToSign);
	}

	@Test
	public void testBCFile() {

		File fileToTest = new File("src/test/resources/validation/counterSig.p7m");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(fileToTest));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");
		assertEquals(2, signatures.size());

		boolean foundCounterSignature = false;
		for (XmlDom xmlDom : signatures) {
			String type = xmlDom.getAttribute("Type");
			if (AttributeValue.COUNTERSIGNATURE.equals(type)) {
				foundCounterSignature = true;
			}
			assertTrue(diagnosticData.isBLevelTechnicallyValid(xmlDom.getAttribute("Id")));
		}
		assertTrue(foundCounterSignature);
	}

}
