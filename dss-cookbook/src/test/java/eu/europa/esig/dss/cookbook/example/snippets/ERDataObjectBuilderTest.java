package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.cades.validation.evidencerecord.CAdESEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilder;
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
    }

}
