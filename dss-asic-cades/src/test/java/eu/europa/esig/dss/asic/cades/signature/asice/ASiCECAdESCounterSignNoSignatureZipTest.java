package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.signature.AbstractASiCCAdESCounterSignatureTest;
import eu.europa.esig.dss.cades.signature.CAdESCounterSignatureParameters;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCECAdESCounterSignNoSignatureZipTest extends AbstractASiCCAdESCounterSignatureTest {

    private ASiCWithCAdESService service;

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
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
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return null;
    }

    @Override
    protected CAdESCounterSignatureParameters getCounterSignatureParameters() {
        CAdESCounterSignatureParameters signatureParameters = new CAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<CAdESCounterSignatureParameters> getCounterSignatureService() {
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
