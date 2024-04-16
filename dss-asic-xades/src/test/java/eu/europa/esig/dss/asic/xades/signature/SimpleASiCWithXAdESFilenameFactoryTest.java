/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
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

    @Test
    public void getASiCSEvidenceRecordFilenameTest() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_S);

        Exception exception = assertThrows(NullPointerException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, null));
        assertEquals("EvidenceRecordType shall be defined!", exception.getMessage());

        assertEquals("META-INF/evidencerecord.xml", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));
        assertEquals("META-INF/evidencerecord.ers", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));
    }

    @Test
    public void getASiCEEvidenceRecordFilenameTest() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_E);

        Exception exception = assertThrows(NullPointerException.class, () -> filenameFactory.getEvidenceRecordFilename(asicContent, null));
        assertEquals("EvidenceRecordType shall be defined!", exception.getMessage());

        assertEquals("META-INF/evidencerecord.xml", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD));
        assertEquals("META-INF/evidencerecord.ers", filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD));
    }

    @Test
    public void getASiCSEvidenceRecordManifestFilenameTest() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(ASiCContainerType.ASiC_S);

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

    @Test
    public void getASiCEEvidenceRecordManifestFilenameTest() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();

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
