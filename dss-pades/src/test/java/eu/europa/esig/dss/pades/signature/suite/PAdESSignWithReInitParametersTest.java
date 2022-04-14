package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
public class PAdESSignWithReInitParametersTest extends AbstractPAdESTestSignature {

    private static PAdESSignatureParameters signatureParameters;
    private static PAdESService service;
    private static CertificateVerifier certificateVerifier;

    private String signingAlias;
    private DSSDocument documentToSign;

    @BeforeAll
    public static void initAll() {
        certificateVerifier = new CommonCertificateVerifier();
        service = new PAdESService(certificateVerifier);

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
    }

    private static Stream<Arguments> data() {
        SignatureLevel[] levels = { SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T,
                SignatureLevel.PAdES_BASELINE_LT, SignatureLevel.PAdES_BASELINE_LTA };
        SignaturePackaging[] packagings = { SignaturePackaging.ENVELOPING };
        String[] signers = { GOOD_USER, RSA_SHA3_USER };
        DSSDocument[] documents = { new InMemoryDocument(PAdESSignDocumentsConsequentlyTest.class.getResourceAsStream("/doc.pdf"), "doc.pdf", MimeType.PDF),
                new InMemoryDocument(PAdESSignDocumentsConsequentlyTest.class.getResourceAsStream("/sample.pdf"), "sample.pdf", MimeType.PDF) };
        return random(levels, packagings, signers, documents);
    }

    static Stream<Arguments> random(SignatureLevel[] levels, SignaturePackaging[] packagings, String[] signers, DSSDocument[] documents) {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < levels.length; i++) {
            for (int j = 0; j < packagings.length; j++) {
                for (int m = 0; m < signers.length; m++) {
                    for (int n = 0; n < documents.length; n++) {
                        args.add(Arguments.of(levels[i], packagings[j], signers[m], documents[n]));
                    }
                }
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Sign PAdES {index} : {0} - {1} - {2} - {3}")
    @MethodSource("data")
    public void init(SignatureLevel level, SignaturePackaging packaging, String signer, DSSDocument document) {
        documentToSign = document;
        signingAlias = signer;

        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(level);
        signatureParameters.setSignaturePackaging(packaging);

        CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setAIASource(completeCertificateVerifier.getAIASource());
        certificateVerifier.setCrlSource(completeCertificateVerifier.getCrlSource());
        certificateVerifier.setOcspSource(completeCertificateVerifier.getOcspSource());
        certificateVerifier.setTrustedCertSources(completeCertificateVerifier.getTrustedCertSources());

        service.setTspSource(getGoodTsa());

        super.signAndVerify();
    }

    @Override
    protected DSSDocument sign() {
        PAdESService service = getService();

        DSSDocument toBeSigned = getDocumentToSign();
        PAdESSignatureParameters params = getSignatureParameters();

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(),
                getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        params.reinit();

        return service.signDocument(toBeSigned, params, signatureValue);
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected PAdESService getService() {
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
        return signingAlias;
    }

}
