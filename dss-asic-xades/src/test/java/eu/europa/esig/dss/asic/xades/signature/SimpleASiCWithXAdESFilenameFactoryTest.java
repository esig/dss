package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SimpleASiCWithXAdESFilenameFactoryTest {

    @Test
    public void getASiCSSignatureFilenameTest() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_S);

        filenameFactory.setSignatureFilename("signatures.xml");
        assertEquals("META-INF/signatures.xml", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("META-INF/signatures.xml");
        assertEquals("META-INF/signatures.xml", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signatures.XML");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-S with XAdES container shall have name " +
                "'META-INF/signatures.xml'!", exception.getMessage());

        filenameFactory.setSignatureFilename("signatures001.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-S with XAdES container shall have name " +
                "'META-INF/signatures.xml'!", exception.getMessage());

        filenameFactory.setSignatureFilename("signature.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-S with XAdES container shall have name " +
                "'META-INF/signatures.xml'!", exception.getMessage());

        filenameFactory.setSignatureFilename("META/signatures.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-S with XAdES container shall have name " +
                "'META-INF/signatures.xml'!", exception.getMessage());

        asicContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("test".getBytes(), "META-INF/signatures.xml")));

        filenameFactory.setSignatureFilename("signatures.xml");
        exception = assertThrows(IllegalInputException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("The filename 'META-INF/signatures.xml' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());
    }

    @Test
    public void getASiCESignatureFilenameTest() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_E);

        filenameFactory.setSignatureFilename("signatures.xml");
        assertEquals("META-INF/signatures.xml", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("META-INF/signatures.xml");
        assertEquals("META-INF/signatures.xml", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signatures001.xml");
        assertEquals("META-INF/signatures001.xml", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("META-INF/signatures001.xml");
        assertEquals("META-INF/signatures001.xml", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signaturesAAA.xml");
        assertEquals("META-INF/signaturesAAA.xml", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signaturesAAA001.xml");
        assertEquals("META-INF/signaturesAAA001.xml", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signatures.XML");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-E with XAdES container shall match the template " +
                "'META-INF/signatures*.xml'!", exception.getMessage());

        filenameFactory.setSignatureFilename("signature.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-E with XAdES container shall match the template " +
                "'META-INF/signatures*.xml'!", exception.getMessage());

        filenameFactory.setSignatureFilename("META/signatures.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-E with XAdES container shall match the template " +
                "'META-INF/signatures*.xml'!", exception.getMessage());

        asicContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("test".getBytes(), "META-INF/signatures.xml")));

        filenameFactory.setSignatureFilename("signatures.xml");
        exception = assertThrows(IllegalInputException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("The filename 'META-INF/signatures.xml' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());
    }

    @Test
    public void getASiCEManifestFilenameTest() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_E);

        filenameFactory.setManifestFilename("manifest.xml");
        assertEquals("META-INF/manifest.xml", filenameFactory.getManifestFilename(asicContent));

        filenameFactory.setManifestFilename("META-INF/manifest.xml");
        assertEquals("META-INF/manifest.xml", filenameFactory.getManifestFilename(asicContent));

        filenameFactory.setManifestFilename("manifest.XML");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("A manifest file within ASiC with XAdES container shall have name " +
                "'META-INF/manifest.xml'!", exception.getMessage());

        filenameFactory.setManifestFilename("ASiCManifest.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("A manifest file within ASiC with XAdES container shall have name " +
                "'META-INF/manifest.xml'!", exception.getMessage());

        filenameFactory.setManifestFilename("manifest001.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("A manifest file within ASiC with XAdES container shall have name " +
                "'META-INF/manifest.xml'!", exception.getMessage());

        filenameFactory.setManifestFilename("META/manifest.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("A manifest file within ASiC with XAdES container shall have name " +
                "'META-INF/manifest.xml'!", exception.getMessage());

        asicContent.setManifestDocuments(Collections.singletonList(
                new InMemoryDocument("test".getBytes(), "META-INF/manifest.xml")));

        filenameFactory.setManifestFilename("manifest.xml");
        exception = assertThrows(IllegalInputException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("The filename 'META-INF/manifest.xml' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());
    }

    @Test
    public void getASiCSDataPackageFilenameTest() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_S);

        filenameFactory.setDataPackageFilename("package.zip");
        assertEquals("package.zip", filenameFactory.getDataPackageFilename(asicContent));

        filenameFactory.setDataPackageFilename("package.ZIP");
        assertEquals("package.ZIP", filenameFactory.getDataPackageFilename(asicContent));

        filenameFactory.setDataPackageFilename("data-package.zip");
        assertEquals("data-package.zip", filenameFactory.getDataPackageFilename(asicContent));

        filenameFactory.setDataPackageFilename("META-INF/package.zip");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getDataPackageFilename(asicContent));
        assertEquals("A data package file within ASiC container shall be on the root level!",
                exception.getMessage());

        filenameFactory.setDataPackageFilename("package.txt");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getDataPackageFilename(asicContent));
        assertEquals("A data package filename within ASiC container shall ends with '.zip'!", exception.getMessage());
    }

}
