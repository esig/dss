package eu.europa.esig.dss.pades.extension.suite.dss3592;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.extension.suite.AbstractPAdESTestExtension;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class DSS3592PAdESExpiredTstExtensionTest extends AbstractPAdESTestExtension {

    private FileDocument documentToSign;

    private String signingAlias;
    private Date signingTime;
    private SignatureLevel originalSignatureLevel;

    private CertificateVerifier certificateVerifier;

    @BeforeEach
    public void init() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -2);
        signingTime = calendar.getTime();

        certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setRevocationFallback(true);
    }

    @Override
    protected FileDocument getOriginalDocument() {
        if (documentToSign == null) {
            documentToSign = super.getOriginalDocument();
        }
        return documentToSign;
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        signingAlias = EXPIRED_USER;
        originalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;

        DSSDocument signedDocument = super.getSignedDocument(doc);
        documentToSign = toFileDocument(signedDocument);

        signingAlias = GOOD_USER;
        originalSignatureLevel = SignatureLevel.PAdES_BASELINE_B;
        signingTime = new Date();

        signedDocument = super.getSignedDocument(documentToSign);

        documentToSign = super.getOriginalDocument();

        originalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;
        return signedDocument;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        PAdESSignatureParameters signatureParameters =  super.getSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        return signatureParameters;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        return certificateVerifier;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Expired signature found."));

        certificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert());

        return super.extendSignature(signedDocument);
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        return getKeyStoreTSPSourceByNameAndTime(EXPIRED_TSA, signingTime);
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return originalSignatureLevel;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_LTA;
    }

    private FileDocument toFileDocument(DSSDocument document) {
        try {
            File originalDoc = Files.createTempFile("dss", document.getName()).toFile();
            try (FileOutputStream fos = new FileOutputStream(originalDoc); InputStream is = document.openStream()) {
                Utils.copy(is, fos);
            } catch (IOException e) {
                throw new DSSException("Unable to create the original document", e);
            }
            return new FileDocument(originalDoc);

        } catch (IOException e) {
            fail(e);
            return null;
        }
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
