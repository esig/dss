package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CBAdESLevelCborNotEtsiTest extends AbstractCBAdESTestSignature {

    private DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> service;
    private CBAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new InMemoryDocument("Hello world!".getBytes());

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setSignatureLevel(SignatureLevel.CBOR_NOT_ETSI);

        service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Test
    @Override
    public void signAndVerify() {
        Exception exception = assertThrows(UnsupportedOperationException.class, super::signAndVerify);
        assertEquals("Unsupported signature format 'CBOR-NOT-ETSI'.", exception.getMessage());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

}
