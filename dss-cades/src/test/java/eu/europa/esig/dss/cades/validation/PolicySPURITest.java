package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.wrappers.DiagnosticData;
import eu.europa.esig.dss.validation.wrappers.SignatureWrapper;

public class PolicySPURITest {

	@Test
	public void test() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-728/CADES-B-DETACHED-withpolicy1586434883385020407.cades");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new MockDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(new FileDocument("src/test/resources/validation/dss-728/InfoSelladoTiempo.pdf"));
		validator.setDetachedContents(detachedContents);
		Reports reports = validator.validateDocument();

		validatePolicy(reports);

	}

	@Test
	public void testWithFilePolicy() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-728/CADES-B-DETACHED-withpolicy1586434883385020407.cades");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setPolicyFile(new File("src/test/resources/validation/dss-728/politica_de_firma_anexo_1.pdf"));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(new FileDocument("src/test/resources/validation/dss-728/InfoSelladoTiempo.pdf"));
		validator.setDetachedContents(detachedContents);
		Reports reports = validator.validateDocument();

		validatePolicy(reports);
	}

	private void validatePolicy(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		SignatureWrapper signatureWrapper = signatures.get(0);

		String policyId = diagnosticData.getPolicyId();
		assertEquals("2.16.724.1.3.1.1.2.1.9", policyId);
		assertEquals("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf", signatureWrapper.getPolicyUrl());
		assertFalse(signatureWrapper.isPolicyAsn1Processable());
		assertTrue(signatureWrapper.isPolicyIdentified());
		assertTrue(signatureWrapper.isPolicyStatus());

	}

}
