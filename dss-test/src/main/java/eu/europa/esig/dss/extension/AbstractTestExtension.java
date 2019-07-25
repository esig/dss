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
package eu.europa.esig.dss.extension;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocation;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.signature.UnmarshallingTester;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.x509.tsp.TSPSource;

public abstract class AbstractTestExtension<SP extends AbstractSignatureParameters> extends PKIFactoryAccess {

	protected abstract DSSDocument getOriginalDocument();

	protected abstract DSSDocument getSignedDocument(DSSDocument originalDoc);

	protected abstract SignatureLevel getOriginalSignatureLevel();

	protected abstract SignatureLevel getFinalSignatureLevel();

	protected abstract DocumentSignatureService<SP> getSignatureServiceToExtend();

	protected abstract TSPSource getUsedTSPSourceAtSignatureTime();

	protected abstract TSPSource getUsedTSPSourceAtExtensionTime();

	@Test
	public void test() throws Exception {
		DSSDocument originalDocument = getOriginalDocument();

		DSSDocument signedDocument = getSignedDocument(originalDocument);

		String signedFilePath = "target/" + signedDocument.getName();
		signedDocument.save(signedFilePath);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();
		UnmarshallingTester.unmarshallXmlReports(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		verifyDiagnosticData(diagnosticData);
		verifySimpleReport(reports.getSimpleReport());
		verifyDetailedReport(reports.getDetailedReport());

		checkOriginalLevel(diagnosticData);
		checkBLevelValid(diagnosticData);

		DSSDocument extendedDocument = extendSignature(signedDocument);

		String extendedFilePath = "target/" + extendedDocument.getName();
		extendedDocument.save(extendedFilePath);

		compare(signedDocument, extendedDocument);

		assertNotNull(extendedDocument);
		assertNotNull(extendedDocument.getMimeType());
		assertNotNull(DSSUtils.toByteArray(extendedDocument));
		assertNotNull(extendedDocument.getName());

		validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();

		// reports.print();
		UnmarshallingTester.unmarshallXmlReports(reports);

		diagnosticData = reports.getDiagnosticData();
		verifyDiagnosticData(diagnosticData);
		verifySimpleReport(reports.getSimpleReport());
		verifyDetailedReport(reports.getDetailedReport());

		checkFinalLevel(diagnosticData);
		checkBLevelValid(diagnosticData);
		checkTLevelAndValid(diagnosticData);

		File fileToBeDeleted = new File(originalDocument.getAbsolutePath());
		assertTrue(fileToBeDeleted.exists());
		assertTrue("Cannot delete original document (IO error)", fileToBeDeleted.delete());
		assertFalse(fileToBeDeleted.exists());

		fileToBeDeleted = new File(signedFilePath);
		assertTrue(fileToBeDeleted.exists());
		assertTrue("Cannot delete signed document (IO error)", fileToBeDeleted.delete());
		assertFalse(fileToBeDeleted.exists());

		fileToBeDeleted = new File(extendedFilePath);
		assertTrue(fileToBeDeleted.exists());
		assertTrue("Cannot delete extended document (IO error)", fileToBeDeleted.delete());
		assertFalse(fileToBeDeleted.exists());
	}

	protected void compare(DSSDocument signedDocument, DSSDocument extendedDocument) {
	}

	private DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
		SP extensionParameters = getExtensionParameters();
		DocumentSignatureService<SP> service = getSignatureServiceToExtend();

		DSSDocument extendedDocument = service.extendDocument(signedDocument, extensionParameters);
		assertNotNull(extendedDocument);

		// extendedDocument.save("target/pdf.pdf");

		return extendedDocument;
	}
	
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		checkTimestamps(diagnosticData);

		checkNoDuplicateCompleteCertificates(diagnosticData);
		checkNoDuplicateCompleteRevocationData(diagnosticData);
	}

	private void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {
		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signatureWrapper : allSignatures) {
			List<XmlFoundCertificate> allFoundCertificates = signatureWrapper.getAllFoundCertificates();
			for (XmlFoundCertificate foundCert : allFoundCertificates) {
				assertEquals("Duplicate certificate in " + foundCert.getOrigins(), 1, foundCert.getOrigins().size());
			}
		}
	}

	private void checkNoDuplicateCompleteRevocationData(DiagnosticData diagnosticData) {
		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signatureWrapper : allSignatures) {
			List<XmlFoundRevocation> allFoundRevocations = signatureWrapper.getAllFoundRevocations();
			for (XmlFoundRevocation foundRevocation : allFoundRevocations) {
				assertEquals("Duplicate revocation data in " + foundRevocation.getOrigins(), 1, foundRevocation.getOrigins().size());
			}
		}
	}
	
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		Set<TimestampWrapper> allTimestamps = diagnosticData.getTimestampSet();
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			assertNotNull(timestampWrapper.getProductionTime());
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			assertTrue(timestampWrapper.isSignatureIntact());
			assertTrue(timestampWrapper.isSignatureValid());

			List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
			for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
				assertTrue(xmlDigestMatcher.isDataFound());
				assertTrue(xmlDigestMatcher.isDataIntact());
			}
		}
	}

	protected void verifySimpleReport(SimpleReport simpleReport) {
		assertNotNull(simpleReport);

		List<String> signatureIdList = simpleReport.getSignatureIdList();
		assertTrue(Utils.isCollectionNotEmpty(signatureIdList));

		for (String sigId : signatureIdList) {
			Indication indication = simpleReport.getIndication(sigId);
			assertNotNull(indication);
			if (indication != Indication.TOTAL_PASSED) {
				assertNotNull(simpleReport.getSubIndication(sigId));
			}
			assertNotNull(simpleReport.getSignatureQualification(sigId));
		}
		assertNotNull(simpleReport.getValidationTime());
	}

	protected void verifyDetailedReport(DetailedReport detailedReport) {
		assertNotNull(detailedReport);

		int nbBBBs = detailedReport.getBasicBuildingBlocksNumber();
		assertTrue(nbBBBs > 0);
		for (int i = 0; i < nbBBBs; i++) {
			String id = detailedReport.getBasicBuildingBlocksSignatureId(i);
			assertNotNull(id);
			assertNotNull(detailedReport.getBasicBuildingBlocksIndication(id));
		}

		List<String> signatureIds = detailedReport.getSignatureIds();
		assertTrue(Utils.isCollectionNotEmpty(signatureIds));
		for (String sigId : signatureIds) {
			Indication basicIndication = detailedReport.getBasicValidationIndication(sigId);
			assertNotNull(basicIndication);
			if (!Indication.PASSED.equals(basicIndication)) {
				assertNotNull(detailedReport.getBasicValidationSubIndication(sigId));
			}
		}

		List<String> timestampIds = detailedReport.getTimestampIds();
		if (Utils.isCollectionNotEmpty(timestampIds)) {
			for (String tspId : timestampIds) {
				Indication timestampIndication = detailedReport.getTimestampValidationIndication(tspId);
				assertNotNull(timestampIndication);
				if (!Indication.PASSED.equals(timestampIndication)) {
					assertNotNull(detailedReport.getTimestampValidationSubIndication(tspId));
				}
			}
		}

		for (String sigId : signatureIds) {
			Indication ltvIndication = detailedReport.getLongTermValidationIndication(sigId);
			assertNotNull(ltvIndication);
			if (!Indication.PASSED.equals(ltvIndication)) {
				assertNotNull(detailedReport.getLongTermValidationSubIndication(sigId));
			}
		}

		for (String sigId : signatureIds) {
			Indication archiveDataIndication = detailedReport.getArchiveDataValidationIndication(sigId);
			assertNotNull(archiveDataIndication);
			if (!Indication.PASSED.equals(archiveDataIndication)) {
				assertNotNull(detailedReport.getArchiveDataValidationSubIndication(sigId));
			}
		}
	}

	protected abstract SP getExtensionParameters();

	private void checkOriginalLevel(DiagnosticData diagnosticData) {
		assertEquals(getOriginalSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	private void checkFinalLevel(DiagnosticData diagnosticData) {
		assertEquals(getFinalSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	private void checkBLevelValid(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	private void checkTLevelAndValid(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
