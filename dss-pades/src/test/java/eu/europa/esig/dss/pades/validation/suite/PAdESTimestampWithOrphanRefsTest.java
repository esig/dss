package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class PAdESTimestampWithOrphanRefsTest extends AbstractPAdESTestValidation {
	
	private static DSSDocument document;
	
	@BeforeEach
	public void init() {
		document = new InMemoryDocument(PAdESTimestampWithOrphanRefsTest.class.getResourceAsStream("/validation/dss-1959/pades-tst-with-orphan-refs.pdf"));
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return document;
	}
	
	@Override
	protected void checkDetachedTimestamps(List<TimestampToken> detachedTimestamps) {
		assertTrue(Utils.isCollectionNotEmpty(detachedTimestamps));
		
		for (TimestampToken timestampToken : detachedTimestamps) {
			try {
				PdfDocTimestampRevision pdfRevision = (PdfDocTimestampRevision) timestampToken.getPdfRevision();
				byte[] signedContent = PAdESUtils.getSignedContent(document, pdfRevision.getByteRange());
				
				SignedDocumentValidator timestampValidator = SignedDocumentValidator.fromDocument(new InMemoryDocument(timestampToken.getEncoded()));
				timestampValidator.setCertificateVerifier(new CommonCertificateVerifier());
				timestampValidator.setDetachedContents(Arrays.asList(new InMemoryDocument(signedContent)));
				
				Reports reports = timestampValidator.validateDocument();
				assertNotNull(reports);
				
				DiagnosticData diagnosticData = reports.getDiagnosticData();
				List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
				assertEquals(1, timestampList.size());
				
				TimestampWrapper timestampWrapper = timestampList.get(0);
				assertTrue(timestampWrapper.isMessageImprintDataFound());
				assertTrue(timestampWrapper.isMessageImprintDataIntact());
				
				SimpleReport simpleReport = reports.getSimpleReport();
				assertNotEquals(Indication.FAILED, simpleReport.getIndication(timestampToken.getDSSIdAsString()));
				
			} catch (IOException e) {
				fail(e);
			}
		}
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		int signatureTimestamps = 0;
		int archiveTimestamps = 0;
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++signatureTimestamps;
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++ archiveTimestamps;
			}
		}
		assertEquals(2, signatureTimestamps);
		assertEquals(2, archiveTimestamps);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);

		for (String signatureId : simpleReport.getSignatureIdList()) {
			assertNotEquals(Indication.FAILED, simpleReport.getIndication(signatureId));
		}
	}

}
