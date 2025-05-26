package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.AbstractASiCXAdESCounterSignatureTest;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithXAdESLevelLTWithContainerERCounterSignatureTest extends AbstractASiCXAdESCounterSignatureTest {

    private ASiCWithXAdESService service;
    private DSSDocument signedDocument;

    private Date signingDate;

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        signedDocument = new FileDocument(new File("src/test/resources/validation/evidencerecord/xades-lt-with-er.sce"));
        signingDate = new Date();
    }

    @Override
    protected DSSDocument sign() {
        return signedDocument;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        return new ASiCWithXAdESSignatureParameters();
    }

    @Override
    protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
        XAdESCounterSignatureParameters signatureParameters = new XAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return signedDocument;
    }

    @Override
    protected ASiCWithXAdESService getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<XAdESCounterSignatureParameters> getCounterSignatureService() {
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
        assertEquals("The modification of the signature is not possible! " +
                "Reason : a signature with a filename 'META-INF/signatures001.xml' is covered by another manifest.", exception.getMessage());
    }

}
