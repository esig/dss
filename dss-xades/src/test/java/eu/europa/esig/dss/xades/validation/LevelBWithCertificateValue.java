package eu.europa.esig.dss.xades.validation;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;

public class LevelBWithCertificateValue {

	@Test
	public void test() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument("src/test/resources/validation/BaselineBWithCertificateValues.xml"));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		SimpleReport simpleReport = reports.getSimpleReport();

		List<String> signatureIdList = simpleReport.getSignatureIdList();
		Assert.assertEquals(1, signatureIdList.size());

		String signatureFormat = simpleReport.getSignatureFormat(signatureIdList.get(0));
		Assert.assertEquals(SignatureLevel.XAdES_BASELINE_B, SignatureLevel.valueByName(signatureFormat));
	}
}
