package eu.europa.esig.dss.asic.xades.signature.opendocument;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
public class OpenDocumentSignWithAtomicMethodsTest extends AbstractOpenDocumentTestSignature {

    private static ASiCWithXAdESSignatureParameters signatureParameters;
    private static ASiCWithXAdESService service;
    private static CertificateVerifier certificateVerifier;

    private String signingAlias;
    private DSSDocument documentToSign;

    @BeforeAll
    public static void initAll() {
        certificateVerifier = new CommonCertificateVerifier();
        service = new ASiCWithXAdESService(certificateVerifier);
    }

    protected static Stream<Arguments> data() {
        SignatureLevel[] levels = { SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T,
                SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA };
        String[] signers = { GOOD_USER, RSA_SHA3_USER };
        File folder = new File("src/test/resources/opendocument");
        Collection<File> listFiles = Utils.listFiles(folder,
                new String[] { "odt", "ods", "odp", "odg" }, true);
        DSSDocument[] documents= listFiles.stream().map(FileDocument::new).collect(Collectors.toList()).toArray(new DSSDocument[]{});
        return random(levels, signers, documents);
    }

    static Stream<Arguments> random(SignatureLevel[] levels, String[] signers, DSSDocument[] documents) {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < levels.length; i++) {
            for (int m = 0; m < signers.length; m++) {
                for (int n = 0; n < documents.length; n++) {
                    args.add(Arguments.of(levels[i], signers[m], documents[n]));
                }
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Sign XAdES {index} : {0} - {1} - {2}")
    @MethodSource("data")
    public void init(SignatureLevel level, String signer, DSSDocument document) {
        documentToSign = document;
        signingAlias = signer;

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(level);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

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
        ASiCWithXAdESService service = getService();

        DSSDocument toBeSigned = getDocumentToSign();
        ASiCWithXAdESSignatureParameters params = getSignatureParameters();

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(),
                getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        toBeSigned = createDocumentCopy(toBeSigned);
        params = createSignatureParametersCopy(params);

        return service.signDocument(toBeSigned, params, signatureValue);
    }

    private DSSDocument createDocumentCopy(DSSDocument document) {
        return new InMemoryDocument(DSSUtils.toByteArray(document), document.getName(), document.getMimeType());
    }

    private ASiCWithXAdESSignatureParameters createSignatureParametersCopy(ASiCWithXAdESSignatureParameters signatureParameters) {
        ASiCWithXAdESSignatureParameters signatureParametersCopy = new ASiCWithXAdESSignatureParameters();
        signatureParametersCopy.setSigningCertificate(signatureParameters.getSigningCertificate());
        signatureParametersCopy.setCertificateChain(signatureParameters.getCertificateChain());
        signatureParametersCopy.setSignatureLevel(signatureParameters.getSignatureLevel());
        signatureParametersCopy.setSignaturePackaging(signatureParameters.getSignaturePackaging());
        signatureParametersCopy.bLevel().setSigningDate(signatureParameters.bLevel().getSigningDate());
        signatureParametersCopy.aSiC().setContainerType(signatureParameters.aSiC().getContainerType());
        return signatureParametersCopy;
    }

    @Override
    public void test(DSSDocument fileToTest) {
        // skip
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected ASiCWithXAdESService getService() {
        return service;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
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
