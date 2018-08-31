package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.CommitmentType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DSS817Test {

	@Test
	public void test()  {
		DSSDocument doc = new FileDocument("src/test/resources/dss-817-test.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<String> commitmentTypeIdentifiers = signatureWrapper.getCommitmentTypeIdentifiers();
		assertEquals(1, commitmentTypeIdentifiers.size());
		assertEquals(CommitmentType.ProofOfApproval.getUri(), commitmentTypeIdentifiers.get(0));
	}
	
}
