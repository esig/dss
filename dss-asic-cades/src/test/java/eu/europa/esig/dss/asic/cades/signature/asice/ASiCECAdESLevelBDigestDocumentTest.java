package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ASiCECAdESLevelBDigestDocumentTest extends PKIFactoryAccess {

    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private final DSSDocument ORIGINAL_DOCUMENT = new InMemoryDocument("Hello World !".getBytes(), "test.text");

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new DigestDocument(DigestAlgorithm.SHA256, ORIGINAL_DOCUMENT.getDigest(DigestAlgorithm.SHA256));

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
    }

    @Test
    public void test() {
        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> service.getDataToSign(documentToSign, signatureParameters));
        assertEquals("ASiC container creation is not possible with DigestDocument!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class,
                () -> service.getContentTimestamp(documentToSign, signatureParameters));
        assertEquals("ASiC container creation is not possible with DigestDocument!", exception.getMessage());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
