package eu.europa.esig.dss.pades.signature;

import java.io.File;
import java.util.Arrays;
import java.util.Date;

import org.junit.Before;

import eu.europa.esig.dss.CommitmentType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class PAdESLevelBWithDSATest extends AbstractPAdESTestSignature {

	private DocumentSignatureService<PAdESSignatureParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.bLevel().setCommitmentTypeIndications(Arrays.asList(CommitmentType.ProofOfOrigin.getOid()));
		signatureParameters.bLevel().setClaimedSignerRoles(Arrays.asList("supplier"));
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.DSA);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signatureParameters.setLocation("Luxembourg");
		signatureParameters.setReason("DSS testing");
		signatureParameters.setContactInfo("Jira");

		service = new PAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return DSA_USER;
	}

}
