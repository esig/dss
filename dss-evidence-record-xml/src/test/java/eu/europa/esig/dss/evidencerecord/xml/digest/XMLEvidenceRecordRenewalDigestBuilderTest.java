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
package eu.europa.esig.dss.evidencerecord.xml.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSElement;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSNamespace;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlEvidenceRecord;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import eu.europa.esig.dss.xml.common.xpath.XPathQueryBuilder;
import eu.europa.esig.dss.xml.utils.DOMDocument;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.xpath.XPathUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XMLEvidenceRecordRenewalDigestBuilderTest {

    private final static DSSNamespace XAdES_NAMESPACE = new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "xades132");
    private final static DSSNamespace XAdESEN_NAMESPACE = new DSSNamespace("http://uri.etsi.org/19132/v1.1.1#", "xadesen");

    static {
        XPathUtils.registerNamespace(XMLDSigNamespace.NS);
        XPathUtils.registerNamespace(XAdES_NAMESPACE);
        XPathUtils.registerNamespace(XAdESEN_NAMESPACE);
        XPathUtils.registerNamespace(XMLERSNamespace.XMLERS);
    }

    @Test
    void timeStampRenewalTest() {
        DSSDocument evidenceRecordDocument = new FileDocument("src/test/resources/er-tst.xml");

        XMLEvidenceRecordRenewalDigestBuilder xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(evidenceRecordDocument);
        Digest digest = xmlEvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("A8A15E96AF737AF13D99233447CC83C3B662B285852823698BFF6208877CD7FFF7E79974AFF89D91F12557ECEC3AF3EEA595B4B5C9A6E2FA7B78858691F73008",
                digest.getHexValue());

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, DigestAlgorithm.SHA256);

        digest = xmlEvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("A8A15E96AF737AF13D99233447CC83C3B662B285852823698BFF6208877CD7FFF7E79974AFF89D91F12557ECEC3AF3EEA595B4B5C9A6E2FA7B78858691F73008",
                digest.getHexValue());

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(evidenceRecordDocument)
                .setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);

        digest = xmlEvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("A8A15E96AF737AF13D99233447CC83C3B662B285852823698BFF6208877CD7FFF7E79974AFF89D91F12557ECEC3AF3EEA595B4B5C9A6E2FA7B78858691F73008",
                digest.getHexValue());

        Element evidenceRecordElement = DomUtils.buildDOM(evidenceRecordDocument).getDocumentElement();
        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord(evidenceRecordElement);

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(xmlEvidenceRecord);
        digest = xmlEvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("A8A15E96AF737AF13D99233447CC83C3B662B285852823698BFF6208877CD7FFF7E79974AFF89D91F12557ECEC3AF3EEA595B4B5C9A6E2FA7B78858691F73008",
                digest.getHexValue());

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(xmlEvidenceRecord, DigestAlgorithm.SHA256);

        digest = xmlEvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("A8A15E96AF737AF13D99233447CC83C3B662B285852823698BFF6208877CD7FFF7E79974AFF89D91F12557ECEC3AF3EEA595B4B5C9A6E2FA7B78858691F73008",
                digest.getHexValue());

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(xmlEvidenceRecord)
                .setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);

        digest = xmlEvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("A8A15E96AF737AF13D99233447CC83C3B662B285852823698BFF6208877CD7FFF7E79974AFF89D91F12557ECEC3AF3EEA595B4B5C9A6E2FA7B78858691F73008",
                digest.getHexValue());
    }

    @Test
    void hashTreeRenewalTest() {
        DSSDocument evidenceRecordDocument = new FileDocument("src/test/resources/er-chain-single.xml");

        XMLEvidenceRecordRenewalDigestBuilder xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(evidenceRecordDocument);

        List<Digest> digestGroup = xmlEvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size()); // no detached data

        assertEquals(DigestAlgorithm.SHA256, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("F0752B32133138E6C088FE35B17790D48BE963F77F1D4094B264610DA0F779F1",
                digestGroup.get(0).getHexValue());

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, DigestAlgorithm.SHA512);

        digestGroup = xmlEvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("372922594C52CFFB7B3A8C1203081EC1E1A38BBF32958627F7F123AB2281AC343B21CACD12FB1856B153C74BB7C4C16E641BBA375F99A017C11177CAB38B93A5",
                digestGroup.get(0).getHexValue());

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, DigestAlgorithm.SHA512)
                .setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);

        digestGroup = xmlEvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("DB5D10CC3AC168317DCCA5A7A7C351E25B65ADD0CDA1CF48E28D8C443C483891C8804973B596317E56791F340EC002282CD2A6D9B32B82EF667A41DC63A79366",
                digestGroup.get(0).getHexValue());

        List<DSSDocument> detachedContent = Collections.singletonList(new InMemoryDocument("da2e47f2-53f4-4610-8210-f0f05d67d0c9".getBytes()));

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, DigestAlgorithm.SHA512)
                .setDetachedContent(detachedContent);

        digestGroup = xmlEvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(2, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("372922594C52CFFB7B3A8C1203081EC1E1A38BBF32958627F7F123AB2281AC343B21CACD12FB1856B153C74BB7C4C16E641BBA375F99A017C11177CAB38B93A5",
                digestGroup.get(0).getHexValue());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(1).getAlgorithm());
        assertEquals("01CBF960B28F6C9A1D8127C274E232DE08C077914B46DA9FBCA504DEDD6E6B4CC894AB9233833101503308F33A96117921D22A70485BF0B6C00E0F0915B70B3F",
                digestGroup.get(1).getHexValue());


        Element evidenceRecordElement = DomUtils.buildDOM(evidenceRecordDocument).getDocumentElement();
        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord(evidenceRecordElement);

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(xmlEvidenceRecord);

        digestGroup = xmlEvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size()); // no detached data

        assertEquals(DigestAlgorithm.SHA256, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("F0752B32133138E6C088FE35B17790D48BE963F77F1D4094B264610DA0F779F1",
                digestGroup.get(0).getHexValue());

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(xmlEvidenceRecord, DigestAlgorithm.SHA512);

        digestGroup = xmlEvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("372922594C52CFFB7B3A8C1203081EC1E1A38BBF32958627F7F123AB2281AC343B21CACD12FB1856B153C74BB7C4C16E641BBA375F99A017C11177CAB38B93A5",
                digestGroup.get(0).getHexValue());

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(xmlEvidenceRecord, DigestAlgorithm.SHA512)
                .setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);

        digestGroup = xmlEvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("DB5D10CC3AC168317DCCA5A7A7C351E25B65ADD0CDA1CF48E28D8C443C483891C8804973B596317E56791F340EC002282CD2A6D9B32B82EF667A41DC63A79366",
                digestGroup.get(0).getHexValue());

        xmlEvidenceRecordRenewalDigestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(xmlEvidenceRecord, DigestAlgorithm.SHA512)
                .setDetachedContent(detachedContent);

        digestGroup = xmlEvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(2, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("372922594C52CFFB7B3A8C1203081EC1E1A38BBF32958627F7F123AB2281AC343B21CACD12FB1856B153C74BB7C4C16E641BBA375F99A017C11177CAB38B93A5",
                digestGroup.get(0).getHexValue());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(1).getAlgorithm());
        assertEquals("01CBF960B28F6C9A1D8127C274E232DE08C077914B46DA9FBCA504DEDD6E6B4CC894AB9233833101503308F33A96117921D22A70485BF0B6C00E0F0915B70B3F",
                digestGroup.get(1).getHexValue());
    }

    @Test
    void nullTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> new XMLEvidenceRecordRenewalDigestBuilder((DSSDocument) null));
        assertEquals("Document cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> new XMLEvidenceRecordRenewalDigestBuilder((XmlEvidenceRecord) null));
        assertEquals("EvidenceRecord cannot be null!", exception.getMessage());

        DSSDocument evidenceRecordDocument = new FileDocument("src/test/resources/er-tst.xml");

        exception = assertThrows(NullPointerException.class, () -> new XMLEvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());

        Element evidenceRecordElement = DomUtils.buildDOM(evidenceRecordDocument).getDocumentElement();
        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord(evidenceRecordElement);
        exception = assertThrows(NullPointerException.class, () -> new XMLEvidenceRecordRenewalDigestBuilder(xmlEvidenceRecord, null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
    }

    @Test
    void invalidFormatTest() {
        Exception exception = assertThrows(IllegalInputException.class, () ->
                new XMLEvidenceRecordRenewalDigestBuilder(new FileDocument("src/test/resources/Signature-C-LT.p7m")));
        assertTrue(exception.getMessage().contains("An XML file is expected : Unable to parse content (XML expected)"));

        exception = assertThrows(IllegalInputException.class, () ->
                new XMLEvidenceRecordRenewalDigestBuilder(new FileDocument("src/test/resources/sample-c14n.xml")));
        assertEquals("No Evidence Record found within the provided document with name 'sample-c14n.xml'! " +
                "Please ensure the Evidence Record is present at the root level of the provided document.", exception.getMessage());
    }

    @Test
    void xadesEmbeddedInclusiveCanonicalizationTstRenewalTest() {
        DSSDocument xadesDocument = new FileDocument("src/test/resources/er-within-xades-inclusive.xml");

        Exception exception = assertThrows(IllegalInputException.class, () -> new XMLEvidenceRecordRenewalDigestBuilder(xadesDocument));
        assertEquals("No Evidence Record found within the provided document with name 'er-within-xades-inclusive.xml'! " +
                "Please ensure the Evidence Record is present at the root level of the provided document.", exception.getMessage());

        Document document = DomUtils.buildDOM(xadesDocument);

        Element erElement = XPathUtils.getElement(document, XPathQueryBuilder.fromCurrentPosition().elements(
                XMLDSigElement.SIGNATURE, XMLDSigElement.OBJECT, DSSElement.fromDefinition("QualifyingProperties", XAdES_NAMESPACE),
                        DSSElement.fromDefinition("UnsignedProperties", XAdES_NAMESPACE), DSSElement.fromDefinition("UnsignedSignatureProperties", XAdES_NAMESPACE),
                        DSSElement.fromDefinition("SealingEvidenceRecords", XAdESEN_NAMESPACE), XMLERSElement.EVIDENCE_RECORD).build());
        assertNotNull(erElement);

        DSSDocument erDocument = new DOMDocument(erElement);

        XMLEvidenceRecordRenewalDigestBuilder digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(erDocument);
        DSSMessageDigest digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("oUgKbUb7XSTTczrIS3ShU8ECDjDPwRYZ1/qfj/MCrJA=", digest.getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(erDocument).setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("oUgKbUb7XSTTczrIS3ShU8ECDjDPwRYZ1/qfj/MCrJA=", digest.getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(erDocument).setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        // ignored canonicalization, used from the ArchiveTimeStampChain definition
        assertEquals("oUgKbUb7XSTTczrIS3ShU8ECDjDPwRYZ1/qfj/MCrJA=", digest.getBase64Value());

        DSSDocument inMemoryErDoc = new InMemoryDocument(DomUtils.serializeNode(erElement));

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(inMemoryErDoc);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("f7snLyAb51tuevykXVnZ9oa7lhOX/5vxwtSJ2xZNcQE=", digest.getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(inMemoryErDoc).setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("f7snLyAb51tuevykXVnZ9oa7lhOX/5vxwtSJ2xZNcQE=", digest.getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(inMemoryErDoc).setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("f7snLyAb51tuevykXVnZ9oa7lhOX/5vxwtSJ2xZNcQE=", digest.getBase64Value());
    }

    @Test
    void xadesEmbeddedExclusiveCanonicalizationTstRenewalTest() {
        DSSDocument xadesDocument = new FileDocument("src/test/resources/er-within-xades-exclusive.xml");

        Exception exception = assertThrows(IllegalInputException.class, () -> new XMLEvidenceRecordRenewalDigestBuilder(xadesDocument));
        assertEquals("No Evidence Record found within the provided document with name 'er-within-xades-exclusive.xml'! " +
                "Please ensure the Evidence Record is present at the root level of the provided document.", exception.getMessage());

        Document document = DomUtils.buildDOM(xadesDocument);

        Element erElement = XPathUtils.getElement(document, XPathQueryBuilder.fromCurrentPosition().elements(
                XMLDSigElement.SIGNATURE, XMLDSigElement.OBJECT, DSSElement.fromDefinition("QualifyingProperties", XAdES_NAMESPACE),
                DSSElement.fromDefinition("UnsignedProperties", XAdES_NAMESPACE), DSSElement.fromDefinition("UnsignedSignatureProperties", XAdES_NAMESPACE),
                DSSElement.fromDefinition("SealingEvidenceRecords", XAdESEN_NAMESPACE), XMLERSElement.EVIDENCE_RECORD).build());
        assertNotNull(erElement);

        DSSDocument erDocument = new DOMDocument(erElement);

        XMLEvidenceRecordRenewalDigestBuilder digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(erDocument);
        DSSMessageDigest digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("f7snLyAb51tuevykXVnZ9oa7lhOX/5vxwtSJ2xZNcQE=", digest.getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(erDocument).setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        // ignored canonicalization, used from the ArchiveTimeStampChain definition
        assertEquals("f7snLyAb51tuevykXVnZ9oa7lhOX/5vxwtSJ2xZNcQE=", digest.getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(erDocument).setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("f7snLyAb51tuevykXVnZ9oa7lhOX/5vxwtSJ2xZNcQE=", digest.getBase64Value());

        DSSDocument inMemoryErDoc = new InMemoryDocument(DomUtils.serializeNode(erElement));

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(inMemoryErDoc);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("f7snLyAb51tuevykXVnZ9oa7lhOX/5vxwtSJ2xZNcQE=", digest.getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(inMemoryErDoc).setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("f7snLyAb51tuevykXVnZ9oa7lhOX/5vxwtSJ2xZNcQE=", digest.getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(inMemoryErDoc).setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        digest = digestBuilder.buildTimeStampRenewalDigest();
        assertEquals("f7snLyAb51tuevykXVnZ9oa7lhOX/5vxwtSJ2xZNcQE=", digest.getBase64Value());
    }

    @Test
    void xadesEmbeddedChainRenewalTest() {
        DSSDocument xadesDocument = new FileDocument("src/test/resources/er-within-xades-inclusive.xml");
        Document document = DomUtils.buildDOM(xadesDocument);
        Element erElement = XPathUtils.getElement(document, XPathQueryBuilder.fromCurrentPosition().elements(
                XMLDSigElement.SIGNATURE, XMLDSigElement.OBJECT, DSSElement.fromDefinition("QualifyingProperties", XAdES_NAMESPACE),
                DSSElement.fromDefinition("UnsignedProperties", XAdES_NAMESPACE), DSSElement.fromDefinition("UnsignedSignatureProperties", XAdES_NAMESPACE),
                DSSElement.fromDefinition("SealingEvidenceRecords", XAdESEN_NAMESPACE), XMLERSElement.EVIDENCE_RECORD).build());
        assertNotNull(erElement);

        DSSDocument erDocument = new DOMDocument(erElement);

        XMLEvidenceRecordRenewalDigestBuilder digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(erDocument);
        List<Digest> digestGroup = digestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());
        assertEquals("xsyR8DoDclDgj7VuNhJSFYq9RSOmGc2rT3qahZaLDhM=", digestGroup.get(0).getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(erDocument).setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
        digestGroup = digestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());
        assertEquals("xsyR8DoDclDgj7VuNhJSFYq9RSOmGc2rT3qahZaLDhM=", digestGroup.get(0).getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(erDocument).setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        digestGroup = digestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());
        assertEquals("kxfp2XAeD7aw+JUahVqzNERhdUNpH7K3BwI4W/vYK2I=", digestGroup.get(0).getBase64Value());

        DSSDocument inMemoryErDoc = new InMemoryDocument(DomUtils.serializeNode(erElement));

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(inMemoryErDoc);
        digestGroup = digestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());
        assertEquals("kxfp2XAeD7aw+JUahVqzNERhdUNpH7K3BwI4W/vYK2I=", digestGroup.get(0).getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(inMemoryErDoc).setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
        digestGroup = digestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());
        assertEquals("kxfp2XAeD7aw+JUahVqzNERhdUNpH7K3BwI4W/vYK2I=", digestGroup.get(0).getBase64Value());

        digestBuilder = new XMLEvidenceRecordRenewalDigestBuilder(inMemoryErDoc).setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        digestGroup = digestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());
        assertEquals("kxfp2XAeD7aw+JUahVqzNERhdUNpH7K3BwI4W/vYK2I=", digestGroup.get(0).getBase64Value());
    }

}
