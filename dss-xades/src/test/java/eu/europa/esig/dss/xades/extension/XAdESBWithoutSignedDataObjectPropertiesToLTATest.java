package eu.europa.esig.dss.xades.extension;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESBWithoutSignedDataObjectPropertiesToLTATest {

	@Test
	public void test() throws Exception {
		DSSDocument toSignDocument = new FileDocument("src/test/resources/XAdESBWithoutSignedDataObjectProperties.xml");
		CertificateService certService = new CertificateService();
		MockPrivateKeyEntry signerEntry = certService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		XAdESService service = new XAdESService(new CommonCertificateVerifier());
		service.setTspSource(new MockTSPSource(new CertificateService().generateTspCertificate(SignatureAlgorithm.RSA_SHA256)));

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		parameters.setSigningCertificate(signerEntry.getCertificate());
		parameters.setCertificateChain(signerEntry.getCertificateChain());
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		DSSDocument extendDocument = service.extendDocument(toSignDocument, parameters);
		// extendDocument.save("target/result.xml");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		SimpleReport simpleReport = reports.getSimpleReport();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		Assert.assertEquals(SignatureLevel.XAdES_BASELINE_LTA.toString(), diagnosticData.getSignatureFormat(simpleReport.getFirstSignatureId()));
	}

}
