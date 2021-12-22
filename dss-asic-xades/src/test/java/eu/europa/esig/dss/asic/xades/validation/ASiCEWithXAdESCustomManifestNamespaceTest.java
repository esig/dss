package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithXAdESCustomManifestNamespaceTest extends AbstractASiCWithXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/container-with-custom-manifest-namespace.asice");
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        super.checkContainerInfo(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);

        List<XmlManifestFile> manifestFiles = containerInfo.getManifestFiles();
        assertEquals(1, manifestFiles.size());

        XmlManifestFile xmlManifestFile = manifestFiles.get(0);
        assertEquals("META-INF/manifest.xml", xmlManifestFile.getFilename());
        assertEquals("META-INF/signatures-1.xml", xmlManifestFile.getSignatureFilename());
        assertEquals(1, xmlManifestFile.getEntries().size());
        assertEquals("hello.txt", xmlManifestFile.getEntries().get(0));
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertFalse(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateReferences()));
        assertFalse(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertFalse(timestampWrapper.isMessageImprintDataIntact());
        assertFalse(timestampWrapper.isSignatureValid());
    }

}
