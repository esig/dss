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
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collection;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SACounterSignatureType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class CounterSignatureValidationTest extends PKIFactoryAccess {

	@SuppressWarnings("unchecked")
	@Test
	public void test() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/validation/counterSig.p7m");

		CMSSignedData cms = new CMSSignedData(document.openStream());
		Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
		assertEquals(1, signers.size());

		Store<X509CertificateHolder> certificates = cms.getCertificates();

		SignerInformation signerInformation = signers.iterator().next();

		Collection<X509CertificateHolder> matches = certificates.getMatches(signerInformation.getSID());
		X509CertificateHolder cert = matches.iterator().next();

		SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(cert);

		assertTrue(signerInformation.verify(verifier));

		SignerInformationStore counterSignatures = signerInformation.getCounterSignatures();
		for (SignerInformation counterSigner : counterSignatures) {

			Collection<X509CertificateHolder> matchesCounter = certificates.getMatches(counterSigner.getSID());
			X509CertificateHolder counterCert = matchesCounter.iterator().next();

			SignerInformationVerifier counterVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(counterCert);

			assertTrue(counterSigner.verify(counterVerifier));
		}

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		for (SignatureWrapper signatureWrapper : signatures) {
			assertTrue(signatureWrapper.isDigestValuePresent());
			assertTrue(signatureWrapper.isDigestValueMatch());
			assertTrue(signatureWrapper.isSignatureIntact());
			assertTrue(signatureWrapper.isSignatureValid());
		}
	}

	@SuppressWarnings("rawtypes")
	@Test
	public void test2() {
		DSSDocument document = new FileDocument("src/test/resources/validation/signedFile.pdf.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(6, signatures.size()); // 3 sig + 3 counter-sig

		int nbSig = 0;
		int nbCounter = 0;
		int nbCounterOfCounter = 0;
		for (SignatureWrapper signatureWrapper : signatures) {
			assertTrue(signatureWrapper.isDigestValuePresent());
			assertTrue(signatureWrapper.isDigestValueMatch());
			assertTrue(signatureWrapper.isSignatureIntact());
			assertTrue(signatureWrapper.isSignatureValid());

			if (signatureWrapper.isCounterSignature()) {
				nbCounter++;

				SignatureWrapper parent = signatureWrapper.getParent();
				assertNotNull(parent);
				if (parent.isCounterSignature()) {
					nbCounterOfCounter++;
				}

			} else {
				nbSig++;
			}
		}
		assertEquals(3, nbSig);
		assertEquals(3, nbCounter);
		assertEquals(1, nbCounterOfCounter);

		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReportJaxb.getSignatureValidationReport();
		assertEquals(6, signatureValidationReports.size());

		int nbCounterSig = 0;
		for (SignatureValidationReportType signatureValidationReportType : signatureValidationReports) {
			SignatureAttributesType signatureAttributes = signatureValidationReportType.getSignatureAttributes();
			List<Object> signingTimeOrSigningCertificateOrDataObjectFormat = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
			for (Object attribute : signingTimeOrSigningCertificateOrDataObjectFormat) {
				if (attribute instanceof JAXBElement) {
					JAXBElement e = (JAXBElement) attribute;
					if (e.getDeclaredType().equals(SACounterSignatureType.class)) {
						nbCounterSig++;
					}
				}
			}
		}
		assertEquals(3, nbCounterSig);
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
