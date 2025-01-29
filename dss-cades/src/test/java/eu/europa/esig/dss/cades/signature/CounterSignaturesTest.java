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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CounterSignaturesTest extends AbstractPkiFactoryTestValidation {

	private String signingAlias;

	@Test
	void test() throws Exception {
		DSSDocument doc = new InMemoryDocument("Hello".getBytes());

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());

		signingAlias = GOOD_USER;

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
//		parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

		ToBeSigned dataToSign = service.getDataToSign(doc, parameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(doc, parameters, signatureValue);

		verify(signedDocument);

		SignedDocumentValidator validator = getValidator(signedDocument);
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		String mainSignatureId = signatures.iterator().next().getId();

		// 1st counter-signature (on main signature)
		signingAlias = GOOD_USER_WITH_PSEUDO;

		CAdESCounterSignatureParameters counterSignatureParameters = new CAdESCounterSignatureParameters();
		CertificateToken firstCounterSigner = getSigningCert();
		counterSignatureParameters.setSigningCertificate(firstCounterSigner);
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);

		// Doesn't work, digest algorithm is not part of the SignedData.digestAlgorithms
		// (not added in
		// org.bouncycastle.cms.CMSSignedData.replaceSigners(CMSSignedData,
		// SignerInformationStore) for counter-signatures)
		// ticket to be created
		// RFC 5652 : The collection is intended to list the message digest algorithms
		// employed by all of the signers, in any order, to facilitate one-pass
		// signature verification.
		// +
		// eu.europa.esig.dss.cades.validation.CAdESSignature.getMessageDigestReferenceValidation(DSSDocument,
		// byte[]) only considers the first one
//		counterSignatureParameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA384);
//		counterSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

		ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
		SignatureValue counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument counterSignedDocument = service.counterSignSignature(signedDocument, counterSignatureParameters, counterSignatureValue);

//		counterSignedDocument.save("target/test1cc.p7s");

		verify(counterSignedDocument);

		// 2nd counter-signature (on main signature)
		signingAlias = EE_GOOD_USER;

		counterSignatureParameters = new CAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);

		dataToBeCounterSigned = service.getDataToBeCounterSigned(counterSignedDocument, counterSignatureParameters);
		counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument secondCounterSignedDocument = service.counterSignSignature(counterSignedDocument, counterSignatureParameters, counterSignatureValue);

//		secondCounterSignedDocument.save("target/test2cc.p7s");

		verify(secondCounterSignedDocument);

		validator = getValidator(secondCounterSignedDocument);
		signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		AdvancedSignature mainSignature = signatures.iterator().next();
		assertEquals(mainSignatureId, mainSignature.getId());
		List<AdvancedSignature> counterSignatures = mainSignature.getCounterSignatures();
		assertEquals(2, counterSignatures.size());
		for (AdvancedSignature advancedSignature : counterSignatures) {
			assertNotNull(advancedSignature.getMasterSignature());
			assertEquals(mainSignatureId, advancedSignature.getMasterSignature().getId());
		}
		AdvancedSignature firstCounterSignature = counterSignatures.get(0);
		String firstCounterSignatureId = firstCounterSignature.getId();

		// order is not guaranteed
		// assertEquals(firstCounterSigner,
		// firstCounterSignature.getSigningCertificateToken());

		// 3rd counter-signature (on 1st counter-signature)
		signingAlias = GOOD_USER_WITH_CRL_AND_OCSP;

		final CAdESCounterSignatureParameters counterSignatureParametersForCounterSignature = new CAdESCounterSignatureParameters();
		counterSignatureParametersForCounterSignature.setSigningCertificate(getSigningCert());
		counterSignatureParametersForCounterSignature.setCertificateChain(getCertificateChain());
		counterSignatureParametersForCounterSignature.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		counterSignatureParametersForCounterSignature.setSignatureIdToCounterSign(firstCounterSignatureId);

		// see https://github.com/bcgit/bc-java/issues/769
		Exception exception = assertThrows(UnsupportedOperationException.class,
				() -> service.getDataToBeCounterSigned(secondCounterSignedDocument, counterSignatureParametersForCounterSignature));
		assertEquals("Nested counter signatures are not supported with CAdES!", exception.getMessage());
		
//		thirdCounterSignedDocument.save("target/third.p7s");
//
//		verify(thirdCounterSignedDocument);
//
//		validator = getValidator(thirdCounterSignedDocument);
//		signatures = validator.getSignatures();
//		assertEquals(1, signatures.size());
//		mainSignature = signatures.iterator().next();
//		assertEquals(mainSignatureId, mainSignature.getId());
//		counterSignatures = mainSignature.getCounterSignatures();
//		assertEquals(2, counterSignatures.size());
//		for (AdvancedSignature counterSignatureLevel1 : counterSignatures) {
//			assertNotNull(counterSignatureLevel1.getMasterSignature());
//			assertEquals(mainSignatureId, counterSignatureLevel1.getMasterSignature().getId());
//			if (counterSignatureLevel1.getId().equals(firstCounterSignatureId)) {
//				List<AdvancedSignature> counterSignaturesLevel2 = counterSignatureLevel1.getCounterSignatures();
//				assertEquals(1, counterSignaturesLevel2.size());
//				assertEquals(firstCounterSignatureId, counterSignaturesLevel2.get(0).getMasterSignature().getId());
//			}
//		}

	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getSignatureValue());
		}
	}

	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {

			if (!Indication.NO_SIGNATURE_FOUND.equals(signatureValidationReport.getSignatureValidationStatus().getMainIndication())) {
				SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());

				SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
				assertNotNull(signatureIdentifier);

				assertNotNull(signatureIdentifier.getSignatureValue());
				assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
			}
		}
	}

}
