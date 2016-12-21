package eu.europa.esig.dss.cades.extension;

import static org.junit.Assert.assertFalse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

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
		validator.setDetachedContents(detachedContents);
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		// The ordering of attributes inside the SET is wrong. The attributes must be ordering by their tags and length
		// Since all the attributes have the same tag, the length decide the order, and the messageDigest should be
		// before the signingTime
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test(expected = DSSException.class)
	public void testExtend() throws Exception {
		CertificateService certificateService = new CertificateService();

		CAdESService service = new CAdESService(new CommonCertificateVerifier());
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256)));

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		DSSDocument detachedContent = new FileDocument(DETACHED_DOC_PATH);
		parameters.setDetachedContents(Arrays.asList(detachedContent));
		DSSDocument extendDocument = service.extendDocument(new FileDocument(SIGNED_DOC_PATH), parameters);

	}

}
