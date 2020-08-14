package eu.europa.esig.dss.xades.signature;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

@Tag("slow")
public class XAdESTimestampCanonicalizationTest extends AbstractXAdESTestSignature {
	
	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private static Stream<Arguments> data() {
		Object[] canonicalizations = { Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
				Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS };
		Object[] packagings = { SignaturePackaging.ENVELOPED, SignaturePackaging.ENVELOPING, 
				SignaturePackaging.DETACHED, SignaturePackaging.INTERNALLY_DETACHED };
		return combine(canonicalizations, packagings);
	}

	static Stream<Arguments> combine(Object[] canonicalizations, Object[] packagings) {
		List<Arguments> args = new ArrayList<>();
		for (int i = 0; i < canonicalizations.length; i++) {
			for (int j = 0; j < canonicalizations.length; j++) {
				for (int k = 0; k < packagings.length; k++) {
					args.add(Arguments.of(canonicalizations[i], canonicalizations[j], packagings[k]));
				}
			}
		}
		return args.stream();
	}

	@ParameterizedTest(name = "Canonicalization {index} : {0} - {1} - {2}")
	@MethodSource("data")
	public void test(String contentTstC14N, String otherTstC14N, SignaturePackaging packaging) {
		documentToSign = new FileDocument(new File("src/test/resources/sample-c14n.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(packaging);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		signatureParameters.setContentTimestampParameters(new XAdESTimestampParameters(DigestAlgorithm.SHA256, contentTstC14N));
		signatureParameters.setSignatureTimestampParameters(new XAdESTimestampParameters(DigestAlgorithm.SHA256, otherTstC14N));
		signatureParameters.setArchiveTimestampParameters(new XAdESTimestampParameters(DigestAlgorithm.SHA256, otherTstC14N));

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		
		TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));

		super.signAndVerify();
	}

	@Override
	public void signAndVerify() {
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(documentToSign);
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
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