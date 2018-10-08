package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class ASN1Policy extends PKIFactoryAccess {

	@Test
	public void testAR() throws Exception {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/AD-RB.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<String, DSSDocument>();
		signaturePoliciesByUrl.put("http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_0.der",
				new InMemoryDocument(getClass().getResourceAsStream("/validation/PA_PAdES_AD_RB_v1_0.der")));
		signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper firstSignature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(firstSignature.isBLevelTechnicallyValid());

		assertTrue(firstSignature.isPolicyPresent());
		assertTrue(firstSignature.isPolicyAsn1Processable());
		assertTrue(firstSignature.isPolicyIdentified());
		assertTrue(firstSignature.getPolicyStatus());

	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
