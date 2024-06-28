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
package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CAdESEvidenceRecordDigestBuilderTest {

    @Test
    void cadesNoErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/C-B-B-basic-der.p7m");

        assertEquals("5C0298EC96A31CAF0248164B7B6899EE17455ABAE48C6C456FF1DF1E4D23ECAE",
                new CAdESEvidenceRecordDigestBuilder(document).build().getHexValue());
        assertEquals("6BCF5B2674047D7DF93E205FE94FC20FED2FCE0B",
                new CAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA1).build().getHexValue());
        assertEquals("05354C18148851D018A26A338059CC78BB636ABB12F76A4B6E3671FB",
                new CAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA224).build().getHexValue());
        assertEquals("5C0298EC96A31CAF0248164B7B6899EE17455ABAE48C6C456FF1DF1E4D23ECAE",
                new CAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("07970EDEDBDE66AE5E28C984FFC6739B62C5AE3164E2DFE81C64431267BC104BA3800F250D368669BE12D7FB8345C29B40F258FB705CF5A510C72E89F24B53C9",
                new CAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512).build().getHexValue());
        assertEquals("07970EDEDBDE66AE5E28C984FFC6739B62C5AE3164E2DFE81C64431267BC104BA3800F250D368669BE12D7FB8345C29B40F258FB705CF5A510C72E89F24B53C9",
                new CAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512).setParallelEvidenceRecord(false).build().getHexValue());
        // TODO : disabled because of BC issue. See https://github.com/bcgit/bc-java/issues/1585
        //  assertEquals("07970EDEDBDE66AE5E28C984FFC6739B62C5AE3164E2DFE81C64431267BC104BA3800F250D368669BE12D7FB8345C29B40F258FB705CF5A510C72E89F24B53C9",
        //          new CAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    void cadesWithErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/C-E-ERS-basic-der.p7m");

        assertEquals("6F29495CC39F94044E13B94DC913EAF001C50A8710DEE14D1589BE5098ECE6E7C722AFA31EF0D6EB7FF21A9521DB0EF0153D657DECC60CDFD9B9A31A92F68535",
                new CAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512).build().getHexValue());

        assertEquals("6F29495CC39F94044E13B94DC913EAF001C50A8710DEE14D1589BE5098ECE6E7C722AFA31EF0D6EB7FF21A9521DB0EF0153D657DECC60CDFD9B9A31A92F68535",
                new CAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512).setParallelEvidenceRecord(false).build().getHexValue());
        // TODO : disabled because of BC issue. See https://github.com/bcgit/bc-java/issues/1585
        //  assertEquals("07970EDEDBDE66AE5E28C984FFC6739B62C5AE3164E2DFE81C64431267BC104BA3800F250D368669BE12D7FB8345C29B40F258FB705CF5A510C72E89F24B53C9",
        //          new CAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    void cadesLtWithErTest() {
        DSSDocument signature = new FileDocument("src/test/resources/validation/evidence-record/Signature-C-LT-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.p7m");
        DSSDocument er = new FileDocument("src/test/resources/validation/evidence-record/evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.ers");

        // embed ER within CMS
        CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(signature);
        SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        ASN1Primitive primitiveEr = DSSASN1Utils.toASN1Primitive(DSSASN1Utils.getDEREncoded(DSSUtils.toByteArray(er)));
        unsignedAttributes = unsignedAttributes.add(OID.id_aa_er_internal, primitiveEr);
        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, new SignerInformationStore(Collections.singleton(signerInformation)));

        DSSDocument cadesWithEr = new CMSSignedDocument(cmsSignedData);

        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).build().getHexValue());
        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    void cadesDetachedTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/C-B-B-basic.p7m");
        DSSDocument detachedDoc = new InMemoryDocument("test 123".getBytes());

        assertEquals("DF07A33A7C644C737CCC9EC1257C7C5EB1614918B19CE205737F9617AD923A05",
                new CAdESEvidenceRecordDigestBuilder(document).setDetachedContent(null).build().getHexValue());
        assertEquals("DF07A33A7C644C737CCC9EC1257C7C5EB1614918B19CE205737F9617AD923A05",
                new CAdESEvidenceRecordDigestBuilder(document).setDetachedContent(detachedDoc).build().getHexValue());

        List<Digest> digests = new CAdESEvidenceRecordDigestBuilder(document).setDetachedContent(detachedDoc).buildExternalEvidenceRecordDigest();
        assertEquals(2, digests.size());
        assertEquals("DF07A33A7C644C737CCC9EC1257C7C5EB1614918B19CE205737F9617AD923A05", digests.get(0).getHexValue());
        assertEquals("F7EF53D21502321EAECB78BB405B7FF266253B4A27D89B9B8C4DA5847CDD1B9D", digests.get(1).getHexValue());
    }

    @Test
    void cadesDetachedWithErTest() {
        DSSDocument signature = new FileDocument("src/test/resources/validation/evidence-record/C-B-B-detached.p7s");
        DSSDocument er = new FileDocument("src/test/resources/validation/evidence-record/evidence-record-C-B-B-detached.ers");
        DSSDocument originalDoc = new FileDocument("src/test/resources/validation/evidence-record/sample.zip");

        // embed ER within CMS
        CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(signature);
        SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();
        ASN1Primitive primitiveEr = DSSASN1Utils.toASN1Primitive(DSSASN1Utils.getDEREncoded(DSSUtils.toByteArray(er)));
        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        Attribute erAttribute = new Attribute(OID.id_aa_er_external, new DERSet(primitiveEr));
        asn1EncodableVector.add(erAttribute);
        AttributeTable unsignedAttributes = new AttributeTable(asn1EncodableVector);
        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, new SignerInformationStore(Collections.singleton(signerInformation)));

        DSSDocument cadesWithEr = new CMSSignedDocument(cmsSignedData);

        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).build().getHexValue());
        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());

        List<Digest> digests = new CAdESEvidenceRecordDigestBuilder(cadesWithEr).setDetachedContent(originalDoc)
                .setParallelEvidenceRecord(true).buildExternalEvidenceRecordDigest();
        assertEquals(2, digests.size());
        assertArrayEquals(signature.getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());
        assertArrayEquals(originalDoc.getDigestValue(DigestAlgorithm.SHA256), digests.get(1).getValue());
    }

    @Test
    void cadesDoubleSigWithErTest() {
        DSSDocument signature = new FileDocument("src/test/resources/validation/evidence-record/Double-C-B-B-basic.p7m");
        DSSDocument er = new FileDocument("src/test/resources/validation/evidence-record/evidence-record-Double-C-B-B-basic.ers");

        // embed ER within CMS
        CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(signature);
        boolean erAdded = false;

        List<SignerInformation> signerInformationList = new ArrayList<>();
        for (SignerInformation signerInformation : cmsSignedData.getSignerInfos()) {
            if (!erAdded) {
                ASN1Primitive primitiveEr = DSSASN1Utils.toASN1Primitive(DSSASN1Utils.getDEREncoded(DSSUtils.toByteArray(er)));
                ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
                Attribute erAttribute = new Attribute(OID.id_aa_er_internal, new DERSet(primitiveEr));
                asn1EncodableVector.add(erAttribute);
                AttributeTable unsignedAttributes = new AttributeTable(asn1EncodableVector);
                signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
                erAdded = true;
            }
            signerInformationList.add(signerInformation);
        }
        cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, new SignerInformationStore(signerInformationList));

        DSSDocument cadesWithEr = new CMSSignedDocument(cmsSignedData);

        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).build().getHexValue());
        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());

        // check with not DER-encoded CMS
        cadesWithEr = new InMemoryDocument(DSSASN1Utils.getEncoded(cmsSignedData));

        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).build().getHexValue());
        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithEr, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    void cadesDoubleSigWithTwoErsTest() {
        DSSDocument signature = new FileDocument("src/test/resources/validation/evidence-record/Double-C-B-B-basic.p7m");
        DSSDocument er = new FileDocument("src/test/resources/validation/evidence-record/evidence-record-Double-C-B-B-basic.ers");

        // embed ER within CMS
        CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(signature);

        List<SignerInformation> signerInformationList = new ArrayList<>();
        for (SignerInformation signerInformation : cmsSignedData.getSignerInfos()) {
            ASN1Primitive primitiveEr = DSSASN1Utils.toASN1Primitive(DSSASN1Utils.getDEREncoded(DSSUtils.toByteArray(er)));
            ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
            Attribute erAttribute = new Attribute(OID.id_aa_er_internal, new DERSet(primitiveEr));
            asn1EncodableVector.add(erAttribute);
            AttributeTable unsignedAttributes = new AttributeTable(asn1EncodableVector);
            signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
            signerInformationList.add(signerInformation);
        }
        cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, new SignerInformationStore(signerInformationList));

        DSSDocument cadesWithErs = new CMSSignedDocument(cmsSignedData);

        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithErs, DigestAlgorithm.SHA256).build().getHexValue());
        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithErs, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        Exception exception = assertThrows(IllegalInputException.class, () ->
                new CAdESEvidenceRecordDigestBuilder(cadesWithErs, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build());
        assertEquals("The CMSSignedData contains multiple evidence record attributes! Unable to compute hash.", exception.getMessage());
    }

    @Test
    void cadesWithTwoErAttrsTest() {
        DSSDocument signature = new FileDocument("src/test/resources/validation/evidence-record/Double-C-E-ERS-basic.p7m");
        DSSDocument er = new FileDocument("src/test/resources/validation/evidence-record/evidence-record-Double-C-E-ERS-basic.ers");

        // embed ER within CMS
        CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(signature);

        boolean erAdded = false;
        List<SignerInformation> signerInformationList = new ArrayList<>();
        for (SignerInformation signerInformation : cmsSignedData.getSignerInfos()) {
            if (!erAdded) {
                ASN1Primitive primitiveEr = DSSASN1Utils.toASN1Primitive(DSSASN1Utils.getDEREncoded(DSSUtils.toByteArray(er)));
                AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
                if (unsignedAttributes != null) {
                    ASN1EncodableVector asn1EncodableVector = unsignedAttributes.toASN1EncodableVector();
                    Attribute erAttribute = new Attribute(OID.id_aa_er_internal, new DERSet(primitiveEr));
                    asn1EncodableVector.add(erAttribute);
                    unsignedAttributes = new AttributeTable(asn1EncodableVector);
                    signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
                    erAdded = true;
                }
            }
            signerInformationList.add(signerInformation);
        }
        cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, new SignerInformationStore(signerInformationList));

        DSSDocument cadesWithTwoErs = new CMSSignedDocument(cmsSignedData);

        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithTwoErs, DigestAlgorithm.SHA256).build().getHexValue());
        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithTwoErs, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithTwoErs, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithTwoErs, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());

        // check with not DER-encoded CMS
        cadesWithTwoErs = new InMemoryDocument(DSSASN1Utils.getEncoded(cmsSignedData));

        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithTwoErs, DigestAlgorithm.SHA256).build().getHexValue());
        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithTwoErs, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithTwoErs, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
        assertNotEquals(new CAdESEvidenceRecordDigestBuilder(signature, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue(),
                new CAdESEvidenceRecordDigestBuilder(cadesWithTwoErs, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    void nullTest() {
        Exception exception = assertThrows(NullPointerException.class,
                () -> new CAdESEvidenceRecordDigestBuilder(null));
        assertEquals("Signature document cannot be null!", exception.getMessage());

        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/C-B-B-basic.p7m");
        exception = assertThrows(NullPointerException.class,
                () -> new CAdESEvidenceRecordDigestBuilder(document, null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
    }

    @Test
    void notCmsTest() {
        DSSDocument document = new InMemoryDocument("test 123".getBytes());
        Exception exception = assertThrows(DSSException.class,
                () -> new CAdESEvidenceRecordDigestBuilder(document).build());
        assertEquals("Not a valid CAdES file", exception.getMessage());
    }

}
