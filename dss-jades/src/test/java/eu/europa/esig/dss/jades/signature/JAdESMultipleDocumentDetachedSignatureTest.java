package eu.europa.esig.dss.jades.signature;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;

public class JAdESMultipleDocumentDetachedSignatureTest extends AbstractJAdESMultipleDocumentSignatureTest {

	private JAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns;
	private JAdESService jadesService;

	@BeforeEach
	public void init() throws Exception {
		documentToSigns = Arrays.<DSSDocument> asList(new FileDocument("src/test/resources/sample.json"),
				new FileDocument("src/test/resources/sample.png"),
				new InMemoryDocument("Hello World!".getBytes(), "helloWorld"));
		
		jadesService = new JAdESService(getOfflineCertificateVerifier());

		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return documentToSigns;
	}

	@Override
	protected MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return jadesService;
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentToSigns;
	}

}
