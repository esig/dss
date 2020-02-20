package signature;

import java.io.File;
import java.util.Arrays;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class JAdESLevelBTest extends AbstractJAdESTestSignature {

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private DSSDocument documentToSign;

	private Date signingDate;
	private TimestampToken contentTimestamp;

	@BeforeEach
	public void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		signingDate = new Date();
		contentTimestamp = service.getContentTimestamp(documentToSign, getSignatureParameters());
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		if (contentTimestamp != null) {
			signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
		}
		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setLocality("Kehlen");
		signatureParameters.bLevel().setSignerLocation(signerLocation);
		//signatureParameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA512);
		signatureParameters.bLevel().setCommitmentTypeIndications(Arrays.asList(CommitmentType.ProofOfCreation.getOid()));
		signatureParameters.bLevel().setClaimedSignerRoles(Arrays.asList("Manager", "Administrator"));
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
