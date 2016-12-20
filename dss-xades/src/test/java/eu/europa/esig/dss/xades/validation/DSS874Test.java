package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.xml.security.utils.Base64;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DSS874Test {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss874/sellosFNMT-XAdES_A.xml");
		File policyDocument = new File("src/test/resources/validation/dss874/policy.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesById = new HashMap<String, DSSDocument>();
		signaturePoliciesById.put("2.16.724.1.3.1.1.2.1.9", new FileDocument(policyDocument));
		signaturePolicyProvider.setSignaturePoliciesById(signaturePoliciesById);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());

		SignatureWrapper signatureWrapper = signatures.get(0);
		assertTrue(signatureWrapper.isPolicyStatus());
		assertTrue(signatureWrapper.isPolicyIdentified());
		assertEquals("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf", signatureWrapper.getPolicyUrl());
	}

	@Test
	public void test2() throws IOException {
		File policyDocument = new File("src/test/resources/validation/dss874/policy.pdf");
		byte[] byteArray = Utils.toByteArray(new FileInputStream(policyDocument));

		byte[] asn1SignaturePolicyDigest = DSSUtils.digest(DigestAlgorithm.SHA1, byteArray);

		assertEquals("G7roucf600+f03r/o0bAOQ6WAs0=", Base64.encode(asn1SignaturePolicyDigest));
	}

}
