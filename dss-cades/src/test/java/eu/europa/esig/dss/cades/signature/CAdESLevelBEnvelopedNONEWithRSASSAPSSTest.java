package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class CAdESLevelBEnvelopedNONEWithRSASSAPSSTest extends AbstractCAdESTestSignature {

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
            if (SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSASSA_PSS, digestAlgorithm, MaskGenerationFunction.MGF1) != null) {
                args.add(Arguments.of(digestAlgorithm));
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Combination {index} of RSASSA-PSS and digest algorithm {0}")
    @MethodSource("data")
    public void init(DigestAlgorithm digestAlgo) {
        documentToSign = new InMemoryDocument("Hello World".getBytes());

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(digestAlgo);
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);

        service = new CAdESService(getOfflineCertificateVerifier());

        super.signAndVerify();
    }

    @Override
    public void signAndVerify() {
    }

    @Override
    protected DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);

        byte[] originalDigest = DSSUtils.digest(signatureParameters.getDigestAlgorithm(), dataToSign.getBytes());
        Digest digest = new Digest(signatureParameters.getDigestAlgorithm(), originalDigest);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSASSA_PSS, signatureParameters.getDigestAlgorithm());
        SignatureValue signatureValue = getToken().signDigest(digest, signatureAlgorithm, getPrivateKeyEntry());
        return service.signDocument(documentToSign, signatureParameters, signatureValue);
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
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

}
