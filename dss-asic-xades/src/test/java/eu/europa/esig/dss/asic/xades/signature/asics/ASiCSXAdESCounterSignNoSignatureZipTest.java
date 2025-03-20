package eu.europa.esig.dss.asic.xades.signature.asics;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.AbstractASiCXAdESCounterSignatureTest;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCSXAdESCounterSignNoSignatureZipTest extends AbstractASiCXAdESCounterSignatureTest {

    private ASiCWithXAdESService service;

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Test
    @Override
    public void signAndVerify() {
        DSSDocument document = new FileDocument("src/test/resources/signable/test.zip");
        Exception exception = assertThrows(IllegalInputException.class, () -> super.counterSign(document, "id-1"));
        assertEquals("The provided file shall be an ASiC container with signatures inside!", exception.getMessage());
    }


    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        return null;
    }

    @Override
    protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
        XAdESCounterSignatureParameters signatureParameters = new XAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<XAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return null;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
