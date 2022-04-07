package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.signature.AbstractASiCWithCAdESMultipleDocumentsTestSignature;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCSWithCAdESMultipleDocumentsTestSignature extends AbstractASiCWithCAdESMultipleDocumentsTestSignature {

    @Override
    protected MimeType getExpectedMime() {
        return MimeType.ASICS;
    }

    @Override
    protected void checkExtractedContent(ASiCContent asicContent) {
        super.checkExtractedContent(asicContent);

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals("package.zip", asicContent.getRootLevelSignedDocuments().get(0).getName());
        assertTrue(Utils.isCollectionNotEmpty(asicContent.getContainerDocuments()));

        assertEquals(1, asicContent.getSignatureDocuments().size());

        DSSDocument signatureDocument = asicContent.getSignatureDocuments().get(0);
        assertEquals("META-INF/signature.p7s", signatureDocument.getName());
        assertNotNull(DSSUtils.toCMSSignedData(signatureDocument));

        assertFalse(Utils.isCollectionNotEmpty(asicContent.getManifestDocuments()));
        assertFalse(Utils.isCollectionNotEmpty(asicContent.getArchiveManifestDocuments()));
        assertFalse(Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()));
        assertFalse(Utils.isCollectionNotEmpty(asicContent.getUnsupportedDocuments()));
    }

}
