package eu.europa.esig.dss.pades.extension.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;

public class PDFTimestampingTest extends PKIFactoryAccess {
	
	@Test
	public void test() {

		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		PAdESSignatureParameters extendParams = new PAdESSignatureParameters();
		
		extendParams.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
		extendParams.setSigningCertificate(getSigningCert());
		DSSDocument extendedDoc = service.extendDocument(doc, extendParams);
		
		PDFDocumentValidator validator = new PDFDocumentValidator(extendedDoc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		
		assertEquals(0, simpleReport.getSignaturesCount());
		assertEquals(0, simpleReport.getSignatureIdList().size());
		assertNotNull(simpleReport.getDocumentFilename());
		
		assertEquals(1, simpleReport.getTimestampIdList().size());
		assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(simpleReport.getFirstTimestampId()));
		assertNull(detailedReport.getFirstSignatureId());
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getTimestampList().size());
		
		TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
		assertEquals(TimestampType.CONTENT_TIMESTAMP, timestampWrapper.getType());
		
		CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
		assertNotNull(signingCertificate);
		
		List<CertificateSourceType> sources = signingCertificate.getSources();
		assertTrue(Utils.isCollectionNotEmpty(sources));
		boolean timestampSource = false;
		for (CertificateSourceType source : sources) {
			if (CertificateSourceType.TIMESTAMP.equals(source)) {
				timestampSource = true;
			}
		}
		assertTrue(timestampSource);
		
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
