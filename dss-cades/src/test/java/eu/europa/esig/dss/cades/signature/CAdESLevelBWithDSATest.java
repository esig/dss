package eu.europa.esig.dss.cades.signature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;

@RunWith(Parameterized.class)
public class CAdESLevelBWithDSATest extends AbstractCAdESTestSignature {

	private static final String HELLO_WORLD = "Hello World";

	private DocumentSignatureService<CAdESSignatureParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private final DigestAlgorithm messageDigestAlgo;
	private final DigestAlgorithm digestAlgo;

	@Parameters(name = "Combination {index} of message-digest algorithm {0} + digest algorithm {1}")
	public static Collection<Object[]> data() {
		List<DigestAlgorithm> digestAlgos = Arrays.asList(DigestAlgorithm.SHA1, DigestAlgorithm.SHA224,
				DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512, DigestAlgorithm.SHA3_224,
				DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512);

		List<Object[]> data = new ArrayList<Object[]>();
		for (DigestAlgorithm digest1 : digestAlgos) {
			for (DigestAlgorithm digest2 : digestAlgos) {
				data.add(new Object[] { digest1, digest2 });
			}
		}
		return data;
	}

	public CAdESLevelBWithDSATest(DigestAlgorithm messageDigestAlgo, DigestAlgorithm digestAlgo) {
		this.messageDigestAlgo = messageDigestAlgo;
		this.digestAlgo = digestAlgo;
	}

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.DSA);
		signatureParameters.setDigestAlgorithm(digestAlgo);
		signatureParameters.setReferenceDigestAlgorithm(messageDigestAlgo);

		service = new CAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
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
