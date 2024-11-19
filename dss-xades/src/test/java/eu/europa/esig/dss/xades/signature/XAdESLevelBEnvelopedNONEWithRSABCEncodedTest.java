package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

@Tag("slow")
class XAdESLevelBEnvelopedNONEWithRSABCEncodedTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
            SignatureAlgorithm algorithm = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSA, digestAlgorithm);
            if (algorithm != null && Utils.isStringNotEmpty(algorithm.getUri())) {
                args.add(Arguments.of(digestAlgorithm));
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Combination {index} of RSA with digest algorithm {0}")
    @MethodSource("data")
    void init(DigestAlgorithm digestAlgo) {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(digestAlgo);

        service = new XAdESService(getOfflineCertificateVerifier());

        super.signAndVerify();
    }

    @Override
    public void signAndVerify() {
    }

    @Override
    protected DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);

        // Compute the digest before the signature + encode (specific RSA without PSS)
        byte[] originalDigest = DSSUtils.digest(signatureParameters.getDigestAlgorithm(), dataToSign.getBytes());
        Digest digest = new Digest(signatureParameters.getDigestAlgorithm(),
                encodeRSADigest(signatureParameters.getDigestAlgorithm(), originalDigest));

        SignatureValue signatureValue = getToken().signDigest(digest, getPrivateKeyEntry());
        return service.signDocument(documentToSign, signatureParameters, signatureValue);
    }

    private byte[] encodeRSADigest(final DigestAlgorithm digestAlgorithm, final byte[] digest) {
        try {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgorithm.getOid()), DERNull.INSTANCE);
            DigestInfo digestInfo = new DigestInfo(algId, digest);
            return digestInfo.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new DSSException("Unable to encode digest", e);
        }
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
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

}
