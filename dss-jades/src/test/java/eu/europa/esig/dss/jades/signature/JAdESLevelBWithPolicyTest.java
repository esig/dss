package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class JAdESLevelBWithPolicyTest extends AbstractJAdESTestSignature {

	private static final String HTTP_SPURI_TEST = "http://spuri.test";
	private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
	private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;

	@BeforeEach
	public void init() {
		service = new JAdESService(getCompleteCertificateVerifier());
		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		
		Policy signaturePolicy = new Policy();
		signaturePolicy.setId("urn:oid:" + SIGNATURE_POLICY_ID);
		signaturePolicy.setDescription(SIGNATURE_POLICY_DESCRIPTION);
		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA1);
		signaturePolicy.setDigestValue(new byte[] { 'd', 'i', 'g', 'e', 's', 't', 'v', 'a', 'l', 'u', 'e' });
		signaturePolicy.setSpuri(HTTP_SPURI_TEST);
		
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
	}
	
	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
		assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyDescription());
	}
	
	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
