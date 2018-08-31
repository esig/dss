package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class EccBrainpoolTest {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/xades-ecc-brainpool.xml");
		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(doc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = sdv.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(EncryptionAlgorithm.ECDSA, signatureWrapper.getEncryptionAlgorithm());
	}

}
