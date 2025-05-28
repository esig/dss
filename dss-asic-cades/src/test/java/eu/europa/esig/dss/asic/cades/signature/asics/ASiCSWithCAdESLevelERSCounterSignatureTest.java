package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.signature.AbstractASiCCAdESCounterSignatureTest;
import eu.europa.esig.dss.cades.signature.CAdESCounterSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSWithCAdESLevelERSCounterSignatureTest extends AbstractASiCCAdESCounterSignatureTest {

    private ASiCWithCAdESService service;
    private DSSDocument signedDocument;

    private Date signingDate;

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
        signedDocument = new FileDocument(new File("src/test/resources/validation/evidencerecord/cades-ers.scs"));
        signingDate = new Date();
    }

    @Override
    protected DSSDocument sign() {
        return signedDocument;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return new ASiCWithCAdESSignatureParameters();
    }

    @Override
    protected CAdESCounterSignatureParameters getCounterSignatureParameters() {
        CAdESCounterSignatureParameters signatureParameters = new CAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return signedDocument;
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<CAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Test
    @Override
    public void signAndVerify() {
        SignedDocumentValidator validator = getValidator(signedDocument);

        List<AdvancedSignature> signatures = validator.getSignatures();
        assertTrue(Utils.isCollectionNotEmpty(signatures));

        AdvancedSignature signature = signatures.get(0);
        String signatureId = signature.getId();

        Exception exception = assertThrows(IllegalInputException.class, () -> counterSign(signedDocument, signatureId));
        assertEquals("Cannot add a counter signature to a CMS containing an evidence record unsigned attribute.", exception.getMessage());
    }

}
