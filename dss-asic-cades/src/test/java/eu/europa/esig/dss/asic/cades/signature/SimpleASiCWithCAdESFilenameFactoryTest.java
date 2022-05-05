package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SimpleASiCWithCAdESFilenameFactoryTest {

    @Test
    public void getASiCSSignatureFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_S);

        filenameFactory.setSignatureFilename("signature.p7s");
        assertEquals("META-INF/signature.p7s", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("META-INF/signature.p7s");
        assertEquals("META-INF/signature.p7s", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signature.P7S");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-S with CAdES container shall have name " +
                "'META-INF/signature.p7s'!", exception.getMessage());

        filenameFactory.setSignatureFilename("signature001.p7s");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-S with CAdES container shall have name " +
                "'META-INF/signature.p7s'!", exception.getMessage());

        filenameFactory.setSignatureFilename("signature.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-S with CAdES container shall have name " +
                "'META-INF/signature.p7s'!", exception.getMessage());

        filenameFactory.setSignatureFilename("META/signature.p7s");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-S with CAdES container shall have name " +
                "'META-INF/signature.p7s'!", exception.getMessage());

        asicContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("test".getBytes(), "META-INF/signature.p7s")));

        filenameFactory.setSignatureFilename("signature.p7s");
        exception = assertThrows(IllegalInputException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("The filename 'META-INF/signature.p7s' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());
    }

    @Test
    public void getASiCESignatureFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_E);

        filenameFactory.setSignatureFilename("signature.p7s");
        assertEquals("META-INF/signature.p7s", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("META-INF/signature.p7s");
        assertEquals("META-INF/signature.p7s", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signature001.p7s");
        assertEquals("META-INF/signature001.p7s", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("META-INF/signature001.p7s");
        assertEquals("META-INF/signature001.p7s", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signatureAAA.p7s");
        assertEquals("META-INF/signatureAAA.p7s", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signatureAAA001.p7s");
        assertEquals("META-INF/signatureAAA001.p7s", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signatures.p7s");
        assertEquals("META-INF/signatures.p7s", filenameFactory.getSignatureFilename(asicContent));

        filenameFactory.setSignatureFilename("signature.P7S");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-E with CAdES container shall match the template " +
                "'META-INF/signature*.p7s'!", exception.getMessage());

        filenameFactory.setSignatureFilename("signature.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-E with CAdES container shall match the template " +
                "'META-INF/signature*.p7s'!", exception.getMessage());

        filenameFactory.setSignatureFilename("META/signature.p7s");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("A signature file within ASiC-E with CAdES container shall match the template " +
                "'META-INF/signature*.p7s'!", exception.getMessage());

        asicContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("test".getBytes(), "META-INF/signature.p7s")));

        filenameFactory.setSignatureFilename("signature.p7s");
        exception = assertThrows(IllegalInputException.class, () ->
                filenameFactory.getSignatureFilename(asicContent));
        assertEquals("The filename 'META-INF/signature.p7s' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());
    }

    @Test
    public void getASiCSTimestampFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_S);

        filenameFactory.setTimestampFilename("timestamp.tst");
        assertEquals("META-INF/timestamp.tst", filenameFactory.getTimestampFilename(asicContent));

        filenameFactory.setTimestampFilename("META-INF/timestamp.tst");
        assertEquals("META-INF/timestamp.tst", filenameFactory.getTimestampFilename(asicContent));

        filenameFactory.setTimestampFilename("timestamp.TST");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getTimestampFilename(asicContent));
        assertEquals("A timestamp file within ASiC-S with CAdES container shall have name " +
                "'META-INF/timestamp.tst'!", exception.getMessage());

        filenameFactory.setTimestampFilename("timestamp001.tst");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getTimestampFilename(asicContent));
        assertEquals("A timestamp file within ASiC-S with CAdES container shall have name " +
                "'META-INF/timestamp.tst'!", exception.getMessage());

        filenameFactory.setTimestampFilename("timestamps.tst");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getTimestampFilename(asicContent));
        assertEquals("A timestamp file within ASiC-S with CAdES container shall have name " +
                "'META-INF/timestamp.tst'!", exception.getMessage());

        filenameFactory.setSignatureFilename("META/timestamp.tst");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getTimestampFilename(asicContent));
        assertEquals("A timestamp file within ASiC-S with CAdES container shall have name " +
                "'META-INF/timestamp.tst'!", exception.getMessage());

        asicContent.setTimestampDocuments(Collections.singletonList(
                new InMemoryDocument("test".getBytes(), "META-INF/timestamp.tst")));

        filenameFactory.setTimestampFilename("timestamp.tst");
        exception = assertThrows(IllegalInputException.class, () ->
                filenameFactory.getTimestampFilename(asicContent));
        assertEquals("The filename 'META-INF/timestamp.tst' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());
    }

    @Test
    public void getASiCETimestampFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_E);

        filenameFactory.setTimestampFilename("timestamp.tst");
        assertEquals("META-INF/timestamp.tst", filenameFactory.getTimestampFilename(asicContent));

        filenameFactory.setTimestampFilename("META-INF/timestamp.tst");
        assertEquals("META-INF/timestamp.tst", filenameFactory.getTimestampFilename(asicContent));

        filenameFactory.setTimestampFilename("timestamp001.tst");
        assertEquals("META-INF/timestamp001.tst", filenameFactory.getTimestampFilename(asicContent));

        filenameFactory.setTimestampFilename("META-INF/timestamp001.tst");
        assertEquals("META-INF/timestamp001.tst", filenameFactory.getTimestampFilename(asicContent));

        filenameFactory.setTimestampFilename("timestampAAA.tst");
        assertEquals("META-INF/timestampAAA.tst", filenameFactory.getTimestampFilename(asicContent));

        filenameFactory.setTimestampFilename("timestampAAA001.tst");
        assertEquals("META-INF/timestampAAA001.tst", filenameFactory.getTimestampFilename(asicContent));

        filenameFactory.setTimestampFilename("timestamps.tst");
        assertEquals("META-INF/timestamps.tst", filenameFactory.getTimestampFilename(asicContent));

        filenameFactory.setTimestampFilename("timestamp.TST");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getTimestampFilename(asicContent));
        assertEquals("A timestamp file within ASiC-E with CAdES container shall match the template " +
                "'META-INF/timestamp*.tst'!", exception.getMessage());

        filenameFactory.setSignatureFilename("META/timestamp.tst");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getTimestampFilename(asicContent));
        assertEquals("A timestamp file within ASiC-E with CAdES container shall match the template " +
                "'META-INF/timestamp*.tst'!", exception.getMessage());

        asicContent.setTimestampDocuments(Collections.singletonList(
                new InMemoryDocument("test".getBytes(), "META-INF/timestamp001.tst")));

        filenameFactory.setTimestampFilename("timestamp001.tst");
        exception = assertThrows(IllegalInputException.class, () ->
                filenameFactory.getTimestampFilename(asicContent));
        assertEquals("The filename 'META-INF/timestamp001.tst' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());
    }

    @Test
    public void getASiCEManifestFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_E);

        filenameFactory.setManifestFilename("ASiCManifest.xml");
        assertEquals("META-INF/ASiCManifest.xml", filenameFactory.getManifestFilename(asicContent));

        filenameFactory.setManifestFilename("META-INF/ASiCManifest.xml");
        assertEquals("META-INF/ASiCManifest.xml", filenameFactory.getManifestFilename(asicContent));

        filenameFactory.setManifestFilename("META-INF/ASiCManifest001.xml");
        assertEquals("META-INF/ASiCManifest001.xml", filenameFactory.getManifestFilename(asicContent));

        filenameFactory.setManifestFilename("META-INF/ASiCManifestAAA.xml");
        assertEquals("META-INF/ASiCManifestAAA.xml", filenameFactory.getManifestFilename(asicContent));

        filenameFactory.setManifestFilename("META-INF/ASiCManifestAAA001.xml");
        assertEquals("META-INF/ASiCManifestAAA001.xml", filenameFactory.getManifestFilename(asicContent));

        filenameFactory.setManifestFilename("ASiCManifest.XML");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("A manifest file within ASiC with CAdES container shall match the template " +
                "'META-INF/ASiCManifest*.xml'!", exception.getMessage());

        filenameFactory.setManifestFilename("manifest.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("A manifest file within ASiC with CAdES container shall match the template " +
                "'META-INF/ASiCManifest*.xml'!", exception.getMessage());

        filenameFactory.setManifestFilename("001ASiCManifest001.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("A manifest file within ASiC with CAdES container shall match the template " +
                "'META-INF/ASiCManifest*.xml'!", exception.getMessage());

        filenameFactory.setManifestFilename("META/ASiCManifest.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("A manifest file within ASiC with CAdES container shall match the template " +
                "'META-INF/ASiCManifest*.xml'!", exception.getMessage());

        asicContent.setManifestDocuments(Collections.singletonList(
                new InMemoryDocument("test".getBytes(), "META-INF/ASiCManifest.xml")));

        filenameFactory.setManifestFilename("ASiCManifest.xml");
        exception = assertThrows(IllegalInputException.class, () ->
                filenameFactory.getManifestFilename(asicContent));
        assertEquals("The filename 'META-INF/ASiCManifest.xml' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());
    }

    @Test
    public void getASiCEArchiveManifestFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_E);

        filenameFactory.setArchiveManifestFilename("ASiCArchiveManifest001.xml");
        assertEquals("META-INF/ASiCArchiveManifest001.xml", filenameFactory.getArchiveManifestFilename(asicContent));

        filenameFactory.setArchiveManifestFilename("META-INF/ASiCArchiveManifest001.xml");
        assertEquals("META-INF/ASiCArchiveManifest001.xml", filenameFactory.getArchiveManifestFilename(asicContent));

        filenameFactory.setArchiveManifestFilename("ASiCArchiveManifestAAA.xml");
        assertEquals("META-INF/ASiCArchiveManifestAAA.xml", filenameFactory.getArchiveManifestFilename(asicContent));

        filenameFactory.setArchiveManifestFilename("META-INF/ASiCArchiveManifestAAA.xml");
        assertEquals("META-INF/ASiCArchiveManifestAAA.xml", filenameFactory.getArchiveManifestFilename(asicContent));

        filenameFactory.setArchiveManifestFilename("ASiCArchiveManifestAAA001.xml");
        assertEquals("META-INF/ASiCArchiveManifestAAA001.xml", filenameFactory.getArchiveManifestFilename(asicContent));

        filenameFactory.setArchiveManifestFilename("ASiCArchiveManifest001.XML");
        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getArchiveManifestFilename(asicContent));
        assertEquals("An archive manifest file within ASiC with CAdES container shall match the template " +
                "'META-INF/ASiCArchiveManifest*.xml'!", exception.getMessage());

        filenameFactory.setArchiveManifestFilename("ASiCManifest.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getArchiveManifestFilename(asicContent));
        assertEquals("An archive manifest file within ASiC with CAdES container shall match the template " +
                "'META-INF/ASiCArchiveManifest*.xml'!", exception.getMessage());

        filenameFactory.setArchiveManifestFilename("001ASiCArchiveManifest001.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getArchiveManifestFilename(asicContent));
        assertEquals("An archive manifest file within ASiC with CAdES container shall match the template " +
                "'META-INF/ASiCArchiveManifest*.xml'!", exception.getMessage());

        filenameFactory.setArchiveManifestFilename("META/ASiCArchiveManifest001.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getArchiveManifestFilename(asicContent));
        assertEquals("An archive manifest file within ASiC with CAdES container shall match the template " +
                "'META-INF/ASiCArchiveManifest*.xml'!", exception.getMessage());

        filenameFactory.setArchiveManifestFilename("ASiCArchiveManifest.xml");
        exception = assertThrows(IllegalArgumentException.class, () ->
                filenameFactory.getArchiveManifestFilename(asicContent));
        assertEquals("An archive manifest file within ASiC with CAdES container cannot be moved " +
                "to a file with name 'META-INF/ASiCArchiveManifest.xml'!", exception.getMessage());

        asicContent.setArchiveManifestDocuments(Collections.singletonList(
                new InMemoryDocument("test".getBytes(), "META-INF/ASiCArchiveManifest001.xml")));

        filenameFactory.setArchiveManifestFilename("ASiCArchiveManifest001.xml");
        exception = assertThrows(IllegalInputException.class, () ->
                filenameFactory.getArchiveManifestFilename(asicContent));
        assertEquals("The filename 'META-INF/ASiCArchiveManifest001.xml' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());
    }

    @Test
    public void getASiCSDataPackageFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

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
