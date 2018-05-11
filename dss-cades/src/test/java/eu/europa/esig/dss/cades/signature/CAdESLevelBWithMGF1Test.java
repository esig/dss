package eu.europa.esig.dss.cades.signature;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;

@RunWith(Parameterized.class)
public class CAdESLevelBWithMGF1Test extends AbstractCAdESTestSignature {

	private static final String HELLO_WORLD = "Hello World";

	private DocumentSignatureService<CAdESSignatureParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private final DigestAlgorithm digestAlgo;

	@Parameters(name = "DigestAlgorithm {index} : {0}")
	public static Collection<DigestAlgorithm> data() {
		return Arrays.asList(DigestAlgorithm.SHA1, DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512
		// SigAlgo Oids are not declared in BC
		// ,DigestAlgorithm.SHA3_224, DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512
		);
	}

	public CAdESLevelBWithMGF1Test(DigestAlgorithm digestAlgo) {
		this.digestAlgo = digestAlgo;
	}

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setDigestAlgorithm(digestAlgo);
		signatureParameters.setMaskGenerationFunction(MaskGenerationFunction.MGF1);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

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
		return GOOD_USER;
	}

}
