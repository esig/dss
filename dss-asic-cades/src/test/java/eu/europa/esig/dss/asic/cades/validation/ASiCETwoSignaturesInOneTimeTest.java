package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.signature.UnmarshallingTester;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ASiCETwoSignaturesInOneTimeTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument document = new FileDocument("src/test/resources/validation/twoSignaturesOneTimeOneSigner.asice");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		
		// signatures must not have the same id
		assertNotEquals(signatureIdList.get(0), signatureIdList.get(1));
		
		UnmarshallingTester.unmarshallXmlReports(reports);
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
