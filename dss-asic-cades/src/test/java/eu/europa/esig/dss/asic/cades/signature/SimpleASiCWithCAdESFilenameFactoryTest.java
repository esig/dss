/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SimpleASiCWithCAdESFilenameFactoryTest {

    @Test
    void getASiCSSignatureFilenameTest() {
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
    void getASiCESignatureFilenameTest() {
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
    void getASiCSTimestampFilenameTest() {
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
    void getASiCETimestampFilenameTest() {
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
    void getASiCEManifestFilenameTest() {
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
    void getASiCEArchiveManifestFilenameTest() {
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
    void getASiCSDataPackageFilenameTest() {
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

    @Test
    void getASiCSEvidenceRecordFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_S);

        Exception exception = assertThrows(NullPointerException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, null));
        assertEquals("EvidenceRecordType shall be defined!", exception.getMessage());

        assertEquals("META-INF/evidencerecord.xml", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename("evidencerecord001.xml");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));
        assertEquals("An evidence record file within ASiC-S with CAdES container shall have name " +
                "'META-INF/evidencerecord.ers' or 'META-INF/evidencerecord.xml'!", exception.getMessage());

        filenameFactory.setEvidenceRecordFilename("evidencerecord.xml");
        assertEquals("META-INF/evidencerecord.xml", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename("evidencerecord.ers");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));
        assertEquals("An XMLERS evidence record file within ASiC container shall end with '.xml' extension!", exception.getMessage());

        assertEquals("META-INF/evidencerecord.ers", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename(null);
        assertEquals("META-INF/evidencerecord.ers", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename("evidencerecord001.ers");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));
        assertEquals("An evidence record file within ASiC-S with CAdES container shall have name " +
                "'META-INF/evidencerecord.ers' or 'META-INF/evidencerecord.xml'!", exception.getMessage());

        filenameFactory.setEvidenceRecordFilename("evidencerecord.xml");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));
        assertEquals("An ERS evidence record file within ASiC container shall end with '.ers' extension!", exception.getMessage());
    }

    @Test
    void getASiCEEvidenceRecordFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_E);

        Exception exception = assertThrows(NullPointerException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, null));
        assertEquals("EvidenceRecordType shall be defined!", exception.getMessage());

        assertEquals("META-INF/evidencerecord001.xml", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));

        asicContent.setEvidenceRecordDocuments(Collections.singletonList(new InMemoryDocument("er".getBytes(), "META-INF/evidencerecord001.xml")));
        assertEquals("META-INF/evidencerecord002.xml", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename("AAAevidencerecordAAA.xml");
        assertEquals("META-INF/AAAevidencerecordAAA.xml", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename("AAAevidencerecordAAA.ers");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));
        assertEquals("An XMLERS evidence record file within ASiC container shall end with '.xml' extension!", exception.getMessage());

        filenameFactory.setEvidenceRecordFilename("META-INF/AAAevidencerecordAAA.xml");
        assertEquals("META-INF/AAAevidencerecordAAA.xml", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));

        asicContent.setEvidenceRecordDocuments(Collections.singletonList(new InMemoryDocument("er".getBytes(), "META-INF/AAAevidencerecordAAA.xml")));
        exception = assertThrows(IllegalInputException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));
        assertEquals("The filename 'META-INF/AAAevidencerecordAAA.xml' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());

        filenameFactory.setEvidenceRecordFilename("META-INF/BBBevidencerecordBBB.xml");
        assertEquals("META-INF/BBBevidencerecordBBB.xml", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename("META-INF/BBBevidenceBBBrecordBBB.xml");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));
        assertEquals("An evidence record file within ASiC-E with CAdES container shall match " +
                "the template 'META-INF/*evidencerecord*(.ers||.xml)'!", exception.getMessage());

        filenameFactory.setEvidenceRecordFilename(null);
        assertEquals("META-INF/evidencerecord001.ers", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));

        asicContent.setEvidenceRecordDocuments(Collections.singletonList(new InMemoryDocument("er".getBytes(), "META-INF/evidencerecord001.ers")));
        assertEquals("META-INF/evidencerecord002.ers", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename("AAAevidencerecordAAA.ers");
        assertEquals("META-INF/AAAevidencerecordAAA.ers", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename("AAAevidencerecordAAA.xml");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));
        assertEquals("An ERS evidence record file within ASiC container shall end with '.ers' extension!", exception.getMessage());

        filenameFactory.setEvidenceRecordFilename("META-INF/AAAevidencerecordAAA.ers");
        assertEquals("META-INF/AAAevidencerecordAAA.ers", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));

        asicContent.setEvidenceRecordDocuments(Collections.singletonList(new InMemoryDocument("er".getBytes(), "META-INF/AAAevidencerecordAAA.ers")));
        exception = assertThrows(IllegalInputException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));
        assertEquals("The filename 'META-INF/AAAevidencerecordAAA.ers' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());

        filenameFactory.setEvidenceRecordFilename("META-INF/BBBevidencerecordBBB.ers");
        assertEquals("META-INF/BBBevidencerecordBBB.ers", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));

        filenameFactory.setEvidenceRecordFilename("META-INF/BBBevidenceBBBrecordBBB.ers");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));
        assertEquals("An evidence record file within ASiC-E with CAdES container shall match " +
                "the template 'META-INF/*evidencerecord*(.ers||.xml)'!", exception.getMessage());
    }

    @Test
    void getASiCSEvidenceRecordManifestFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_S);

        assertEquals("META-INF/ASiCEvidenceRecordManifest001.xml", filenameFactory.getEvidenceRecordManifestFilename(asicContent));

        asicContent.setEvidenceRecordManifestDocuments(Collections.singletonList(new InMemoryDocument("manifest".getBytes(), "META-INF/ASiCEvidenceRecordManifest001.xml")));
        assertEquals("META-INF/ASiCEvidenceRecordManifest002.xml", filenameFactory.getEvidenceRecordManifestFilename(asicContent));

        filenameFactory.setEvidenceRecordManifestFilename("ASiCEvidenceRecordManifestAAA.xml");
        assertEquals("META-INF/ASiCEvidenceRecordManifestAAA.xml", filenameFactory.getEvidenceRecordManifestFilename(asicContent));

        filenameFactory.setEvidenceRecordManifestFilename("META-INF/ASiCEvidenceRecordManifestAAA.xml");
        assertEquals("META-INF/ASiCEvidenceRecordManifestAAA.xml", filenameFactory.getEvidenceRecordManifestFilename(asicContent));

        asicContent.setEvidenceRecordManifestDocuments(Collections.singletonList(new InMemoryDocument("manifest".getBytes(), "META-INF/ASiCEvidenceRecordManifestAAA.xml")));
        Exception exception = assertThrows(IllegalInputException.class, () -> filenameFactory.getEvidenceRecordManifestFilename(asicContent));
        assertEquals("The filename 'META-INF/ASiCEvidenceRecordManifestAAA.xml' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());

        filenameFactory.setEvidenceRecordManifestFilename("META-INF/ASiCEvidenceRecordManifestBBB.xml");
        assertEquals("META-INF/ASiCEvidenceRecordManifestBBB.xml", filenameFactory.getEvidenceRecordManifestFilename(asicContent));

        filenameFactory.setEvidenceRecordManifestFilename("META-INF/001ASiCEvidenceRecordManifest001.xml");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordManifestFilename(asicContent));
        assertEquals("ASiC evidence record manifest file within ASiC container shall match " +
                "the template 'META-INF/ASiCEvidenceRecordManifest*.xml'!", exception.getMessage());
    }

    @Test
    void getASiCEEvidenceRecordManifestFilenameTest() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_E);

        assertEquals("META-INF/ASiCEvidenceRecordManifest001.xml", filenameFactory.getEvidenceRecordManifestFilename(asicContent));

        asicContent.setEvidenceRecordManifestDocuments(Collections.singletonList(new InMemoryDocument("manifest".getBytes(), "META-INF/ASiCEvidenceRecordManifest001.xml")));
        assertEquals("META-INF/ASiCEvidenceRecordManifest002.xml", filenameFactory.getEvidenceRecordManifestFilename(asicContent));

        filenameFactory.setEvidenceRecordManifestFilename("ASiCEvidenceRecordManifestAAA.xml");
        assertEquals("META-INF/ASiCEvidenceRecordManifestAAA.xml", filenameFactory.getEvidenceRecordManifestFilename(asicContent));

        filenameFactory.setEvidenceRecordManifestFilename("META-INF/ASiCEvidenceRecordManifestAAA.xml");

        asicContent.setEvidenceRecordManifestDocuments(Collections.singletonList(new InMemoryDocument("manifest".getBytes(), "META-INF/ASiCEvidenceRecordManifestAAA.xml")));
        Exception exception = assertThrows(IllegalInputException.class, () -> filenameFactory.getEvidenceRecordManifestFilename(asicContent));
        assertEquals("The filename 'META-INF/ASiCEvidenceRecordManifestAAA.xml' cannot be used, " +
                "as a document of the same name is already present within the container!", exception.getMessage());

        filenameFactory.setEvidenceRecordManifestFilename("META-INF/ASiCEvidenceRecordManifestBBB.xml");
        assertEquals("META-INF/ASiCEvidenceRecordManifestBBB.xml", filenameFactory.getEvidenceRecordManifestFilename(asicContent));

        filenameFactory.setEvidenceRecordManifestFilename("META-INF/001ASiCEvidenceRecordManifest001.xml");
        exception = assertThrows(IllegalArgumentException.class, () -> filenameFactory.getEvidenceRecordManifestFilename(asicContent));
        assertEquals("ASiC evidence record manifest file within ASiC container shall match " +
                "the template 'META-INF/ASiCEvidenceRecordManifest*.xml'!", exception.getMessage());
    }

}
