package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCELevelLTAWithCustomManifestNamespaceTest extends AbstractASiCWithCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/asice-level-lta-with-custom-manifest-namespace.sce");
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        super.checkContainerInfo(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);

        List<XmlManifestFile> manifestFiles = containerInfo.getManifestFiles();
        assertEquals(2, manifestFiles.size());

        boolean signatureManifestFound = false;
        boolean tstManifestFound = false;
        for (XmlManifestFile manifestFile : manifestFiles) {
            for (String entryName : manifestFile.getEntries()) {
                assertTrue(Utils.isStringNotBlank(entryName));
            }
            if ("META-INF/ASiCManifest.xml".equals(manifestFile.getFilename())) {
                assertEquals("META-INF/signature001.p7s", manifestFile.getSignatureFilename());
                assertEquals(1, manifestFile.getEntries().size());
                signatureManifestFound = true;
            } else if ("META-INF/ASiCArchiveManifest.xml".equals(manifestFile.getFilename())) {
                assertEquals("META-INF/timestamp001.tst", manifestFile.getSignatureFilename());
                assertEquals(3, manifestFile.getEntries().size());
                tstManifestFound = true;
            }
        }
        assertTrue(signatureManifestFound);
        assertTrue(tstManifestFound);
    }

}
