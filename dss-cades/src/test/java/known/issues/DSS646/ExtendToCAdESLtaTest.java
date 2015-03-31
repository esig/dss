package known.issues.DSS646;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Test;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.mock.MockTSPSource;
import eu.europa.ec.markt.dss.parameter.CAdESSignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.cades.CAdESService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

/**
 * Unit test to fix issue https://esig-dss.atlassian.net/browse/DSS-646
 */
public class ExtendToCAdESLtaTest {

	private static final String SIGNED_DOC_PATH = "src/test/resources/validation/dss-646/CAdES_A_DETACHED.csig";
	private static final String DETACHED_DOC_PATH = "src/test/resources/validation/dss-646/document.pdf";

	@Test
	public void testValidation() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(SIGNED_DOC_PATH));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(new FileDocument(DETACHED_DOC_PATH));
		validator.setDetachedContents(detachedContents );
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testExtend() throws  Exception {
		CertificateService certificateService = new CertificateService();

		CAdESService service = new CAdESService(new CommonCertificateVerifier());
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256), new Date()));

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		DSSDocument detachedContent = new FileDocument(DETACHED_DOC_PATH);
		parameters.setDetachedContent(detachedContent );
		DSSDocument extendDocument = service.extendDocument(new FileDocument(SIGNED_DOC_PATH), parameters);


	}

}
