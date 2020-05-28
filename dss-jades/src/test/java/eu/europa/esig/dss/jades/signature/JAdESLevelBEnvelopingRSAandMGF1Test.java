package eu.europa.esig.dss.jades.signature;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;

@Tag("slow")
public class JAdESLevelBEnvelopingRSAandMGF1Test extends AbstractJAdESTestSignature {

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private JAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private static Stream<Arguments> data() {
		List<Arguments> args = new ArrayList<>();

		for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
			SignatureAlgorithm sa = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSA, digestAlgo, MaskGenerationFunction.MGF1);
			if (sa != null && Utils.isStringNotBlank(sa.getJWAId())) {
				args.add(Arguments.of(digestAlgo));
			}
		}

		return args.stream();
	}

	@ParameterizedTest(name = "Combination {index} of RSA and PSS with digest algorithm {0}")
	@MethodSource("data")
	public void init(DigestAlgorithm digestAlgo) {
		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));

		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(digestAlgo);
		signatureParameters.setMaskGenerationFunction(MaskGenerationFunction.MGF1);

		service = new JAdESService(getOfflineCertificateVerifier());

		super.signAndVerify();
	}

	@Override
	public void signAndVerify() {
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

}