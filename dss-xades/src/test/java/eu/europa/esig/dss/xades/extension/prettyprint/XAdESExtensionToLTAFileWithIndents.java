package eu.europa.esig.dss.xades.extension.prettyprint;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESExtensionToLTAFileWithIndents extends PKIFactoryAccess {
	
	protected XAdESService service;
	protected XAdESSignatureParameters signatureParameters;
	
	@Before
	public void init() {
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.setPrettyPrint(true);

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Test
	public void test() throws Exception {
		
		DSSDocument originalDocument = new FileDocument("src/test/resources/lt_level_with_indents.xml");
		
		DSSDocument ltaLevelSigned = service.extendDocument(originalDocument, signatureParameters);
		// ltaLevelSigned.save("target/fileWithIndentsToLTA.xml");
		validateDocument(ltaLevelSigned);
		
	}
	
	protected void validateDocument(DSSDocument document) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		checkTimestamps(diagnosticData);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		validateDetailedReport(detailedReport);
		assertEquals(SignatureLevel.XAdES_BASELINE_LTA.toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}
	
	private void checkTimestamps(DiagnosticData diagnosticData) {
		Set<TimestampWrapper> allTimestamps = diagnosticData.getAllTimestamps();
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
	
	private void validateDetailedReport(DetailedReport detailedReport) {
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
			assertFalse(Indication.FAILED.equals(basicIndication));
			if (!Indication.PASSED.equals(basicIndication)) {
				assertNotNull(detailedReport.getBasicValidationSubIndication(sigId));
			}
		}

		List<String> timestampIds = detailedReport.getTimestampIds();
		if (Utils.isCollectionNotEmpty(timestampIds)) {
			for (String tspId : timestampIds) {
				Indication timestampIndication = detailedReport.getTimestampValidationIndication(tspId);
				assertNotNull(timestampIndication);
				assertFalse(Indication.FAILED.equals(timestampIndication));
				if (!Indication.PASSED.equals(timestampIndication)) {
					assertNotNull(detailedReport.getTimestampValidationSubIndication(tspId));
				}
			}
		}

		for (String sigId : signatureIds) {
			Indication ltvIndication = detailedReport.getLongTermValidationIndication(sigId);
			assertNotNull(ltvIndication);
			assertFalse(Indication.FAILED.equals(ltvIndication));
			if (!Indication.PASSED.equals(ltvIndication)) {
				assertNotNull(detailedReport.getLongTermValidationSubIndication(sigId));
			}
		}

		for (String sigId : signatureIds) {
			Indication archiveDataIndication = detailedReport.getArchiveDataValidationIndication(sigId);
			assertNotNull(archiveDataIndication);
			assertFalse(Indication.FAILED.equals(archiveDataIndication));
			if (!Indication.PASSED.equals(archiveDataIndication)) {
				assertNotNull(detailedReport.getArchiveDataValidationSubIndication(sigId));
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
