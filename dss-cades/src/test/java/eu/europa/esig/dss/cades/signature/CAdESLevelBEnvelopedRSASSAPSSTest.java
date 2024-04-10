package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESLevelBEnvelopedRSASSAPSSTest extends AbstractCAdESTestSignature {

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();

        for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
            SignatureAlgorithm sa = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSASSA_PSS, digestAlgo);
            if (sa != null && Utils.isStringNotBlank(sa.getUri())) {
                args.add(Arguments.of(digestAlgo));
            }
        }

        return args.stream();
    }

    @ParameterizedTest(name = "Combination {index} of RSASSA-PSS with digest algorithm {0}")
    @MethodSource("data")
    public void init(DigestAlgorithm digestAlgo) {
        documentToSign = new InMemoryDocument("Hello World".getBytes());

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setDigestAlgorithm(digestAlgo);
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

        service = new CAdESService(getOfflineCertificateVerifier());

        super.signAndVerify();
    }

    @Override
    protected DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSASSA_PSS, signatureParameters.getDigestAlgorithm(), null);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureAlgorithm, getPrivateKeyEntry());
        assertEquals(signatureAlgorithm, signatureValue.getAlgorithm());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        return service.signDocument(documentToSign, signatureParameters, signatureValue);
    }

    @Override
    public void signAndVerify() {
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
