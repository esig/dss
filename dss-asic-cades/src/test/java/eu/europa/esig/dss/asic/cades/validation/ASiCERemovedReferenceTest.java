package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ASiCERemovedReferenceTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/removedReference.asice");
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
		int remobedRefsCounter = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
				manifestEntryCounter++;
			}
			if (!digestMatcher.isDataIntact()) {
				brokenRefsCounter++;
			}
			if (!digestMatcher.isDataFound()) {
				remobedRefsCounter++;
			}
			assertNotNull(digestMatcher.getDigestMethod());
			assertNotNull(digestMatcher.getDigestValue());
		}
		assertEquals(1, brokenRefsCounter);
		assertEquals(1, remobedRefsCounter);
		List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
		assertEquals(1, manifestFiles.size());
		List<String> entries = manifestFiles.get(0).getEntries();
		assertNotNull(entries);
		assertEquals(entries.size(), manifestEntryCounter);
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());
		
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}
}
