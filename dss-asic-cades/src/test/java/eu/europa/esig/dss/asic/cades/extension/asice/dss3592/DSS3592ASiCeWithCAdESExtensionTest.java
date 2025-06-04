package eu.europa.esig.dss.asic.cades.extension.asice.dss3592;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.extension.AbstractASiCWithCAdESTestExtension;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class DSS3592ASiCeWithCAdESExtensionTest extends AbstractASiCWithCAdESTestExtension {

    private FileDocument documentToSign;

    private String signingAlias;
    private Date signingTime;
    private SignatureLevel originalSignatureLevel;

    @BeforeEach
    public void init() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -2);
        signingTime = calendar.getTime();
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
        originalSignatureLevel = SignatureLevel.CAdES_BASELINE_T;

        DSSDocument signedDocument = super.getSignedDocument(doc);
        documentToSign = toFileDocument(signedDocument);

        signingAlias = GOOD_USER;
        originalSignatureLevel = SignatureLevel.CAdES_BASELINE_B;
        signingTime = new Date();

        signedDocument = super.getSignedDocument(documentToSign);

        documentToSign = super.getOriginalDocument();

        originalSignatureLevel = SignatureLevel.CAdES_BASELINE_T;
        return signedDocument;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        ASiCWithCAdESSignatureParameters signatureParameters =  super.getSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        return signatureParameters;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setRevocationFallback(true);
        return certificateVerifier;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        return getGoodTsaByTime(signingTime);
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return originalSignatureLevel;
    }

    @Override
    protected void checkOriginalLevel(DiagnosticData diagnosticData) {
        int bLevelCounter = 0;
        int tLevelCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.CAdES_BASELINE_B == signatureWrapper.getSignatureFormat()) {
                ++bLevelCounter;
            } else if (SignatureLevel.CAdES_BASELINE_T == signatureWrapper.getSignatureFormat()) {
                ++tLevelCounter;
            }
        }
        assertEquals(1, bLevelCounter);
        assertEquals(1, tLevelCounter);
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        int ltaLevelCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.CAdES_BASELINE_LTA == signatureWrapper.getSignatureFormat()) {
                ++ltaLevelCounter;
            }
        }
        assertEquals(2, ltaLevelCounter);
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

    @Override
    protected ASiCContainerType getContainerType() {
        return ASiCContainerType.ASiC_E;
    }

}
