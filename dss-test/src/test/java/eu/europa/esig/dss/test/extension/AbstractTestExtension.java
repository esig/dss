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
package eu.europa.esig.dss.test.extension;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractTestExtension<SP extends SerializableSignatureParameters, 
				TP extends SerializableTimestampParameters> extends AbstractPkiFactoryTestValidation {

	protected abstract FileDocument getOriginalDocument();

	protected abstract DSSDocument getSignedDocument(DSSDocument originalDoc);

	protected abstract SignatureLevel getOriginalSignatureLevel();

	protected abstract SignatureLevel getFinalSignatureLevel();

	protected abstract DocumentSignatureService<SP, TP> getSignatureServiceToSign();

	protected abstract DocumentSignatureService<SP, TP> getSignatureServiceToExtend();

	protected abstract TSPSource getUsedTSPSourceAtSignatureTime();

	protected abstract TSPSource getUsedTSPSourceAtExtensionTime();

	@Test
	public void extendAndVerify() throws Exception {
		FileDocument originalDocument = getOriginalDocument();

		DSSDocument signedDocument = getSignedDocument(originalDocument);

		String signedFilePath = "target/" + signedDocument.getName();
		signedDocument.save(signedFilePath);

		onDocumentSigned(signedDocument);
		
		Reports reports = verify(signedDocument);
		checkOriginalLevel(reports.getDiagnosticData());

		DSSDocument extendedDocument = extendSignature(signedDocument);

		String extendedFilePath = "target/" + extendedDocument.getName();
		extendedDocument.save(extendedFilePath);

		compare(signedDocument, extendedDocument);

		onDocumentExtended(extendedDocument);

		reports = verify(extendedDocument);
		checkFinalLevel(reports.getDiagnosticData());
		checkTLevelAndValid(reports.getDiagnosticData());

		File fileToBeDeleted;
		deleteOriginalFile(originalDocument);

		fileToBeDeleted = new File(signedFilePath);
		assertTrue(fileToBeDeleted.exists());
		assertTrue(fileToBeDeleted.delete(), "Cannot delete signed document (IO error)");
		assertFalse(fileToBeDeleted.exists());

		fileToBeDeleted = new File(extendedFilePath);
		assertTrue(fileToBeDeleted.exists());
		assertTrue(fileToBeDeleted.delete(), "Cannot delete extended document (IO error)");
		assertFalse(fileToBeDeleted.exists());
	}

	protected void deleteOriginalFile(FileDocument originalDocument) {
		File fileToBeDeleted = new File(originalDocument.getAbsolutePath());
		assertTrue(fileToBeDeleted.exists());
		assertTrue(fileToBeDeleted.delete(), "Cannot delete original document (IO error)");
		assertFalse(fileToBeDeleted.exists());
	}

	protected void compare(DSSDocument signedDocument, DSSDocument extendedDocument) {
	}

	protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
		SP extensionParameters = getExtensionParameters();
		DocumentSignatureService<SP, TP> service = getSignatureServiceToExtend();

		DSSDocument extendedDocument = service.extendDocument(signedDocument, extensionParameters);
		assertNotNull(extendedDocument);

		// extendedDocument.save("target/pdf.pdf");

		return extendedDocument;
	}

	protected abstract SP getSignatureParameters();

	protected abstract SP getExtensionParameters();

	protected void checkOriginalLevel(DiagnosticData diagnosticData) {
		assertEquals(getOriginalSignatureLevel(), diagnosticData.getFirstSignatureFormat());
	}

	protected void checkFinalLevel(DiagnosticData diagnosticData) {
		assertEquals(getFinalSignatureLevel(), diagnosticData.getFirstSignatureFormat());
	}
	
	protected void checkTLevelAndValid(DiagnosticData diagnosticData) {
        assertTrue(diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
        assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
    }

	@Override
	protected void checkCertificates(DiagnosticData diagnosticData) {
		super.checkCertificates(diagnosticData);
		checkCertificateValuesEncapsulation(diagnosticData);
	}

	protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
		// Signature certificate chain validation
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			List<RelatedCertificateWrapper> certificateValues = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES);
			if (Utils.isCollectionNotEmpty(certificateValues)) {
				List<String> signatureCertificateIds = populateWithRevocationCertificatesRecursively(new ArrayList<>(), signature.getCertificateChain());
				for (CertificateWrapper certificate : certificateValues) {
					assertTrue(signatureCertificateIds.contains(certificate.getId()));
				}
			}
			// Timestamp certificate chain validation
			List<RelatedCertificateWrapper> tstValidationData = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
			if (Utils.isCollectionNotEmpty(tstValidationData)) {
				List<String> timestampCertificateIds = new ArrayList<>();
				for (TimestampWrapper timestamp : signature.getTimestampList()) {
					populateWithRevocationCertificatesRecursively(timestampCertificateIds, timestamp.getCertificateChain());
				}
				for (CertificateWrapper certificate : tstValidationData) {
					assertTrue(timestampCertificateIds.contains(certificate.getId()));
				}
			}
			// Any validation data validation
			List<RelatedCertificateWrapper> anyValidationData = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA);
			if (Utils.isCollectionNotEmpty(anyValidationData)) {
				List<String> certificateIds = populateWithRevocationCertificatesRecursively(new ArrayList<>(), signature.getCertificateChain());
				for (TimestampWrapper timestamp : signature.getTimestampList()) {
					populateWithRevocationCertificatesRecursively(certificateIds, timestamp.getCertificateChain());
				}
				for (CertificateWrapper certificate : anyValidationData) {
					assertTrue(certificateIds.contains(certificate.getId()));
				}
			}
		}
	}

	private List<String> populateWithRevocationCertificatesRecursively(List<String> certIdList, List<CertificateWrapper> certChain) {
		for (CertificateWrapper certificateWrapper : certChain) {
			if (!certIdList.contains(certificateWrapper.getId())) {
				certIdList.add(certificateWrapper.getId());
				for (RevocationWrapper revocationWrapper : certificateWrapper.getCertificateRevocationData()) {
					populateWithRevocationCertificatesRecursively(certIdList, revocationWrapper.getCertificateChain());
				}
			}
		}
		return certIdList;
	}

	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		checkCertificateValuesEncapsulation(diagnosticData);
	}

	protected void checkRevocationDataEncapsulation(DiagnosticData diagnosticData) {
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			List<RelatedRevocationWrapper> sigRevocationWrappers = signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES);
			if (Utils.isCollectionNotEmpty(sigRevocationWrappers)) {
				List<String> revIdList = new ArrayList<>();
				for (CertificateWrapper certificateWrapper : signature.getCertificateChain()) {
					populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
				}
				for (RevocationWrapper revocation : sigRevocationWrappers) {
					assertTrue(revIdList.contains(revocation.getId()));
				}
			}
			List<RelatedRevocationWrapper> tstRevocationWrappers = signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
			if (Utils.isCollectionNotEmpty(tstRevocationWrappers)) {
				List<String> revIdList = new ArrayList<>();
				for (TimestampWrapper timestampWrapper : signature.getTimestampList()) {
					for (CertificateWrapper certificateWrapper : timestampWrapper.getCertificateChain()) {
						populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
					}
				}
				for (RevocationWrapper revocation : tstRevocationWrappers) {
					assertTrue(revIdList.contains(revocation.getId()));
				}
			}
			List<RelatedRevocationWrapper> anyValidationData = signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA);
			if (Utils.isCollectionNotEmpty(anyValidationData)) {
				List<String> revIdList = new ArrayList<>();
				for (CertificateWrapper certificateWrapper : signature.getCertificateChain()) {
					populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
				}
				for (TimestampWrapper timestampWrapper : signature.getTimestampList()) {
					for (CertificateWrapper certificateWrapper : timestampWrapper.getCertificateChain()) {
						populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
					}
				}
				for (RevocationWrapper revocation : anyValidationData) {
					assertTrue(revIdList.contains(revocation.getId()));
				}
			}
		}
	}

	private List<String> populateWithRevocationDataRecursively(List<String> revIdList, List<? extends RevocationWrapper> revocationData) {
		for (RevocationWrapper revocationWrapper : revocationData) {
			if (!revIdList.contains(revocationWrapper.getId())) {
				revIdList.add(revocationWrapper.getId());
				for (CertificateWrapper certificateWrapper : revocationWrapper.getCertificateChain()) {
					populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
				}
			}
		}
		return revIdList;
	}

	protected void onDocumentSigned(DSSDocument signedDocument) {
		assertNotNull(signedDocument);
		assertNotNull(signedDocument.getMimeType());
		assertNotNull(DSSUtils.toByteArray(signedDocument));
		assertNotNull(signedDocument.getName());
	}

	protected void onDocumentExtended(DSSDocument extendedDocument) {
		assertNotNull(extendedDocument);
		assertNotNull(extendedDocument.getMimeType());
		assertNotNull(DSSUtils.toByteArray(extendedDocument));
		assertNotNull(extendedDocument.getName());
	}

}
