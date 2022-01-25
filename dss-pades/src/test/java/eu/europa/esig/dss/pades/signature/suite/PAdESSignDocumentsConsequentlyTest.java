package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

@Tag("slow")
public class PAdESSignDocumentsConsequentlyTest extends AbstractPAdESTestSignature {

    private static PAdESSignatureParameters signatureParameters;
    private static DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
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
        SignatureLevel[] levels = {SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T,
                SignatureLevel.PAdES_BASELINE_LT, SignatureLevel.PAdES_BASELINE_LTA};
        SignaturePackaging[] packagings = {SignaturePackaging.ENVELOPING};
        String[] signers = {GOOD_USER, RSA_SHA3_USER};
        DSSDocument[] documents = { new InMemoryDocument(PAdESSignDocumentsConsequentlyTest.class.getResourceAsStream("/doc.pdf")),
                new InMemoryDocument(PAdESSignDocumentsConsequentlyTest.class.getResourceAsStream("/sample.pdf")) };
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
    protected List<DSSDocument> getDetachedContents() {
        if (SignaturePackaging.DETACHED.equals(signatureParameters.getSignaturePackaging())) {
            return Arrays.asList(getDocumentToSign());
        }
        return Collections.emptyList();
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
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
