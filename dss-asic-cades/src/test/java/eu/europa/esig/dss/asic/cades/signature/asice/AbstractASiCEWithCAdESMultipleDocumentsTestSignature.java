package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.signature.AbstractASiCWithCAdESMultipleDocumentsTestSignature;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCEWithCAdESMultipleDocumentsTestSignature extends AbstractASiCWithCAdESMultipleDocumentsTestSignature {

    @Override
    protected MimeType getExpectedMime() {
        return MimeType.ASICE;
    }

    @Override
    protected boolean isBaselineT() {
        SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
        return SignatureLevel.CAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.CAdES_BASELINE_LT.equals(signatureLevel)
                || SignatureLevel.CAdES_BASELINE_T.equals(signatureLevel);
    }

    @Override
    protected boolean isBaselineLTA() {
        return SignatureLevel.CAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
    }

    @Override
    protected void checkExtractedContent(ASiCContent asicContent) {
        super.checkExtractedContent(asicContent);

        assertNotNull(asicContent.getMimeTypeDocument());
        assertTrue(Utils.isCollectionNotEmpty(asicContent.getSignedDocuments()));

        assertTrue(Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()));
        for (DSSDocument signatureDocument : asicContent.getSignatureDocuments()) {
            assertNotNull(DSSUtils.toCMSSignedData(signatureDocument));
        }

        assertTrue(Utils.isCollectionNotEmpty(asicContent.getManifestDocuments()));

        assertFalse(Utils.isCollectionNotEmpty(asicContent.getUnsupportedDocuments()));
    }

}
