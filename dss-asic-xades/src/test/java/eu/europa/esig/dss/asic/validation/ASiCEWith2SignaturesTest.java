package eu.europa.esig.dss.asic.validation;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ASiCEWith2SignaturesTest {

	@Test
	public void test() {
		DSSDocument asicContainer = new FileDocument("src/test/resources/ASiCEWith2Signatures.bdoc");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(asicContainer);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<String, DSSDocument>();
		signaturePoliciesByUrl.put("https://www.sk.ee/repository/bdoc-spec21.pdf", new FileDocument(new File("src/test/resources/bdoc-spec21.pdf")));
		signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		Reports reports = validator.validateDocument();
		Assert.assertNotNull(reports);
		// reports.print();
		reports = reports.getNextReports();
		Assert.assertNotNull(reports);
		// reports.print();
	}
}
