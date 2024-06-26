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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.cades.validation.evidencerecord.CAdESEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordRenewalDigestBuilder;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordRenewalDigestBuilder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordDigestBuilder;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.List;

public class ERDataObjectBuilderTest {

    @Test
    public void test() throws Exception {

        // tag::xml-er[]
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
        // import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilder;
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.Digest;
        // import eu.europa.esig.dss.model.InMemoryDocument;
        // import javax.xml.crypto.dsig.CanonicalizationMethod;

        // Data object to be protected by en evidence record
        DSSDocument dataObject = new InMemoryDocument("Hello World!".getBytes());

        // Instantiate an XMLEvidenceRecordDataObjectDigestBuilder to create digest for the given data object
        // with a specified digest algorithm
        XMLEvidenceRecordDataObjectDigestBuilder xmlEvidenceRecordDataObjectDigestBuilder =
                new XMLEvidenceRecordDataObjectDigestBuilder(dataObject, DigestAlgorithm.SHA256);

        // Set a canonicalization method (to be used for XML data objects only)
        xmlEvidenceRecordDataObjectDigestBuilder.setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);

        // Builds digests based on the provided configuration
        Digest digest = xmlEvidenceRecordDataObjectDigestBuilder.build();

        // Extract hash value to be included within a preservation system / evidence record
        byte[] value = digest.getValue();
        // end::xml-er[]

        // tag::asn1-er[]
        // import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilder;
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;

        // Instantiate an ASN1EvidenceRecordDataObjectDigestBuilder to create digest for the given data object
        ASN1EvidenceRecordDataObjectDigestBuilder asn1EvidenceRecordDataObjectDigestBuilder =
                new ASN1EvidenceRecordDataObjectDigestBuilder(dataObject, DigestAlgorithm.SHA256);
        // end::asn1-er[]

        List<DSSDocument> detachedContents = new ArrayList<>();

        // tag::xades-er[]
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.FileDocument;
        // import eu.europa.esig.dss.xades.validation.evidencerecord.XAdESEvidenceRecordDigestBuilder;
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;

        // Load XML signature to be protected by an evidence record
        DSSDocument xmlSignatureDocument = new FileDocument("src/test/resources/signature-pool/signedXmlXadesB.xml");

        // Instantiate a XAdESEvidenceRecordDigestBuilder to create digest of an XML signature
        // to be protected by an embedded evidence record
        XAdESEvidenceRecordDigestBuilder xadesEvidenceRecordDigestBuilder =
                new XAdESEvidenceRecordDigestBuilder(xmlSignatureDocument, DigestAlgorithm.SHA512);

        // Optional : Provide a list of detached documents in case of a detached XML signature
        xadesEvidenceRecordDigestBuilder.setDetachedContent(detachedContents);

        // Optional : Identify the signature to be protected by its ID in case of a document with multiple signatures
        xadesEvidenceRecordDigestBuilder.setSignatureId("id-b1e08b419abe3c004c53a18681354918");

        // Optional : Define whether the target evidence record should be created as a parallel
        // evidence record
        // When TRUE : computes hash of the signature ignoring the last xadesen:SealingEvidenceRecords
        // unsigned qualifying property, as the new evidence record would be included within
        // the last xadesen:SealingEvidenceRecords element (parallel evidence record)
        // When FALSE : computes hash of the complete signature element, including all present
        // xadesen:SealingEvidenceRecords elements
        // Default : FALSE (computes digest on the whole signature)
        xadesEvidenceRecordDigestBuilder.setParallelEvidenceRecord(true);
        // end::xades-er[]

        // tag::cades-er[]
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.FileDocument;
        // import eu.europa.esig.dss.cades.validation.evidencerecord.CAdESEvidenceRecordDigestBuilder;
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;

        // Load CMS signature to be protected by an evidence record
        DSSDocument cmsSignatureDocument = new FileDocument("src/test/resources/signature-pool/signedCadesB.p7m");

        // Instantiate a CAdESEvidenceRecordDigestBuilder to create digest of a CMS signature
        // to be protected by an embedded evidence record
        CAdESEvidenceRecordDigestBuilder cadesEvidenceRecordDigestBuilder =
                new CAdESEvidenceRecordDigestBuilder(cmsSignatureDocument, DigestAlgorithm.SHA256);

        // Optional : Provide a detached document in case of a detached CMS signature
        cadesEvidenceRecordDigestBuilder.setDetachedContent(dataObject);

        // Optional : Define whether the target evidence record should be created as a parallel
        // evidence record
        // When TRUE : computes hash of the signature ignoring the last evidence-record attribute
        // (i.e. internal-evidence-record or external-evidence-record) unsigned attribute,
        // as the new evidence record would be included within that attribute
        // When FALSE : computes hash of the complete CMS signature
        // Default : FALSE (computes digest on the whole signature)
        cadesEvidenceRecordDigestBuilder.setParallelEvidenceRecord(true);

        // Use method #build to build signature digest for internal-evidence-record incorporation
        Digest signatureDigest = cadesEvidenceRecordDigestBuilder.build();

        // Use method #buildExternalEvidenceRecordDigest to build a list of digests for
        // external-evidence-record incorporation. The list includes signature digest at
        // the first position, and digest of the detached document at the second
        List<Digest> digests = cadesEvidenceRecordDigestBuilder.buildExternalEvidenceRecordDigest();
        // end::cades-er[]

        // tag::xmlers-renewal-er[]
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
        // import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordRenewalDigestBuilder;
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.Digest;
        // import eu.europa.esig.dss.model.FileDocument;
        // import javax.xml.crypto.dsig.CanonicalizationMethod;
        // import java.util.List;

        // Load RFC 6283 XMLERS evidence record to be renewed
        DSSDocument xmlersEvidenceRecord = new FileDocument("src/test/resources/snippets/evidence-record.xml");

        // Instantiate a XMLEvidenceRecordRenewalDigestBuilder to create digest
        // for evidence record's renewal.
        // NOTE: the class does not perform validation of the provided evidence record.
        XMLEvidenceRecordRenewalDigestBuilder xmlEvidenceRecordRenewalDigestBuilder =
                new XMLEvidenceRecordRenewalDigestBuilder(xmlersEvidenceRecord);

        // Create digest for time-stamp renewal.
        // This method builds digest on a canonicalized value of the last ArchiveTimeStamp element.
        // NOTE: this method uses digest algorithm and canonicalization method defined
        // within the corresponding ArchiveTimeStampChain element
        Digest tstRenewalDigest = xmlEvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();

        // Instantiate builder for hash-tree renewal with a specified digest algorithm
        xmlEvidenceRecordRenewalDigestBuilder =
                new XMLEvidenceRecordRenewalDigestBuilder(xmlersEvidenceRecord, DigestAlgorithm.SHA512);

        // Set the canonicalization method to be used
        xmlEvidenceRecordRenewalDigestBuilder.setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);

        // Set the detached content to compute digest for.
        // NOTE: if not provided, the digest computation for detached content will be ignored.
        xmlEvidenceRecordRenewalDigestBuilder.setDetachedContent(detachedContents);

        // Build a digest group to be protected by a hash-tree renewal time-stamp.
        // This method builds digest on a canonicalized value of ArchiveTimeStampSequence element
        // and provided detached content documents
        List<Digest> digestGroup = xmlEvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        // end::xmlers-renewal-er[]

        // tag::ers-renewal-er[]
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
        // import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordRenewalDigestBuilder;
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.Digest;
        // import eu.europa.esig.dss.model.FileDocument;
        // import java.util.List;

        // Load RFC 4998 ERS evidence record to be renewed
        DSSDocument ersEvidenceRecord = new FileDocument("src/test/resources/snippets/evidence-record.ers");

        // Instantiate a ASN1EvidenceRecordRenewalDigestBuilder to create digest
        // for evidence record's renewal.
        // NOTE: the class does not perform validation of the provided evidence record.
        ASN1EvidenceRecordRenewalDigestBuilder asn1EvidenceRecordRenewalDigestBuilder =
                new ASN1EvidenceRecordRenewalDigestBuilder(ersEvidenceRecord);

        // Create digest for time-stamp renewal.
        // This method builds digest on an encoded value of ArchiveTimeStamp attribute.
        // NOTE: this method uses digest algorithm defined within the first archive-time-stamp
        // of the last ArchiveTimeStampChain
        Digest ersTstRenewalDigest = asn1EvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();

        // Instantiate builder for hash-tree renewal with a specified digest algorithm
        asn1EvidenceRecordRenewalDigestBuilder =
                new ASN1EvidenceRecordRenewalDigestBuilder(ersEvidenceRecord, DigestAlgorithm.SHA512);

        // Set the detached content to compute digest for.
        // NOTE: if not provided, the output will produce an empty list.
        asn1EvidenceRecordRenewalDigestBuilder.setDetachedContent(detachedContents);

        // Build a digest group to be protected by a hash-tree renewal time-stamp.
        // This method builds digest on a concatenated digest of a DER-encoded of
        // ArchiveTimeStampSequence attribute and provided detached content documents
        List<Digest> ersDigestGroup = asn1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        // end::ers-renewal-er[]

    }

}
