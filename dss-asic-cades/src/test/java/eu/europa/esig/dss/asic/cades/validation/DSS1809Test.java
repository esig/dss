package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1809Test extends PKIFactoryAccess {
	
	private static final DSSDocument document = new FileDocument("src/test/resources/validation/ASICE-CAdES-BpLTA-2-BpLTA-DSS5.4.asice");
	
	@Test
	public void test() {
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
		assertTrue(Utils.isCollectionNotEmpty(manifestFiles));
		assertEquals(3, manifestFiles.size());
		
		int archiveTimestampWithManifestCounter = 0;
		List<TimestampWrapper> timestampList = signature.getTimestampList();
		for (TimestampWrapper timestamp : timestampList) {
			if (timestamp.getType().isArchivalTimestamp()) {
				XmlDigestMatcher messageImprint = timestamp.getMessageImprint();
				assertNotNull(messageImprint);
				assertNotNull(messageImprint.getName());
				for (XmlManifestFile manifestFile : manifestFiles) {
					if (messageImprint.getName().equals(manifestFile.getFilename())) {
						assertEquals(manifestFile.getEntries().size(), getNumberOfManifestEntries(timestamp));
						archiveTimestampWithManifestCounter++;
					}
				}
			}
		}
		assertEquals(2, archiveTimestampWithManifestCounter);
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotEquals(Indication.FAILED, detailedReport.getTimestampValidationIndication(timestampList.get(0).getId())); // signature_timestamp
		assertEquals(Indication.FAILED, detailedReport.getTimestampValidationIndication(timestampList.get(1).getId())); // first archive_timestamp
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getTimestampValidationSubIndication(timestampList.get(1).getId())); // first archive_timestamp
		assertNotEquals(Indication.FAILED, detailedReport.getTimestampValidationIndication(timestampList.get(2).getId())); // second archive_timestamp
		
	}
	
	private int getNumberOfManifestEntries(TimestampWrapper timestampWrapper) {
		int counter = 0;
		List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
					counter++;
				}
			}
		}
		
		return counter;
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
