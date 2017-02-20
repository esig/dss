package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DSS1135Test {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1135/factura_ejemplo2_32v1.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		// certificateVerifier.setDataLoader(new CommonsDataLoader());
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<String, DSSDocument>();
		signaturePoliciesByUrl.put("http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
				new FileDocument("src/test/resources/validation/dss1135/politica_de_firma.pdf"));
		signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		String signatureId = diagnosticData.getFirstSignatureId();
		String policyId = diagnosticData.getPolicyId(signatureId);
		assertEquals("http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf", policyId);
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
		String policyUrl = signatureWrapper.getPolicyUrl();
		assertEquals("http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf", policyUrl);
		assertTrue(signatureWrapper.isPolicyIdentified());
		assertTrue(signatureWrapper.isPolicyStatus());
	}

}
