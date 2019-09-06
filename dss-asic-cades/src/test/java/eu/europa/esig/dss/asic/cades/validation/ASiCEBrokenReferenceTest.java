package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ASiCEBrokenReferenceTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/brokenReference.asice");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(3, digestMatchers.size());
		int manifestEntryCounter = 0;
		int brokenRefsCounter = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
				manifestEntryCounter++;
			}
			if (!digestMatcher.isDataIntact()) {
				brokenRefsCounter++;
			}
			assertTrue(digestMatcher.isDataFound());
			assertNotNull(digestMatcher.getDigestMethod());
			assertNotNull(digestMatcher.getDigestValue());
		}
		assertEquals(1, brokenRefsCounter);
		List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
		assertEquals(1, manifestFiles.size());
		List<String> entries = manifestFiles.get(0).getEntries();
		assertNotNull(entries);
		assertEquals(entries.size(), manifestEntryCounter);
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, signatureBBB.getConclusion().getSubIndication());
		
	}

	@Test
	public void testBrokenReferenceAndAlteredManifest() {

		DSSDocument document = new FileDocument("src/test/resources/validation/brokenReferenceAndAlteredManifest.asice");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(simpleReport.getFirstSignatureId());
		assertNotNull(originalDocuments);
		assertEquals(0, originalDocuments.size());
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}
}
