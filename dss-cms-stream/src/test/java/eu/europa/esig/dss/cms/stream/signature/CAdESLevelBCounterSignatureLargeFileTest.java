package eu.europa.esig.dss.cms.stream.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.AbstractCAdESCounterSignatureTest;
import eu.europa.esig.dss.cades.signature.CAdESCounterSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
class CAdESLevelBCounterSignatureLargeFileTest extends AbstractCAdESCounterSignatureTest {

    private CAdESService service;
    private DSSDocument documentToSign;

    private Date signingDate;

    private String signatureId;

    @BeforeEach
    void init() throws Exception {
        service = new CAdESService(getOfflineCertificateVerifier());
        service.setResourcesHandlerBuilder(new TempFileResourcesHandlerBuilder());

        documentToSign = generateLargeFile();
        signingDate = new Date();
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return signatureParameters;
    }

    @Override
    protected CAdESCounterSignatureParameters getCounterSignatureParameters() {
        CAdESCounterSignatureParameters signatureParameters = new CAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        return signatureParameters;
    }

    private DSSDocument generateLargeFile() throws IOException {
        File file = new File("target/large-binary.bin");

        long size = 0x00FFFFFF; // Integer.MAX_VALUE -1
        byte [] data = new byte[(int)size];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(data);

        try (FileOutputStream fos = new FileOutputStream(file)) {
            for (int i = 0; i < 500; i++) {
                fos.write(data);
            }
        }

        return new FileDocument(file);
    }

    @Override
    @Test
    public void signAndVerify() {
        final DSSDocument signedDocument = sign();

        SignedDocumentValidator validator = getValidator(signedDocument);

        List<AdvancedSignature> signatures = validator.getSignatures();
        assertTrue(Utils.isCollectionNotEmpty(signatures));

        AdvancedSignature signature = signatures.get(signatures.size() - 1);
        signatureId = signature.getId();

        DSSDocument counterSigned = counterSign(signedDocument, getSignatureIdToCounterSign());

        assertNotNull(counterSigned.getName());
        assertNotNull(counterSigned.getMimeType());

        checkMimeType(counterSigned);

        validator = getValidator(counterSigned);
        List<AdvancedSignature> signatures2 = validator.getSignatures();

        for (AdvancedSignature sig : signatures) {
            boolean found = false;
            for (AdvancedSignature sig2 : signatures2) {
                if (Utils.areStringsEqual(sig.getId(), sig2.getId())) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, String.format("Signature IDs have changed (before : %s / after : %s", signatures, signatures2));
        }

        verify(counterSigned);
    }

    @Override
    protected String getSignatureIdToCounterSign() {
        return signatureId;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
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

}
