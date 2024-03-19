package eu.europa.esig.dss.evidencerecord.asn1.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilder;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilderFactory;

/**
 * Creates a new instance of {@code eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilder}
 * to compute hashes for RFC 4998 ASN.1  Evidence Record Syntax (ERS) evidence records
 */
public class ASN1EvidenceRecordDataObjectDigestBuilderFactory implements DataObjectDigestBuilderFactory {

    /**
     * Default constructor
     */
    public ASN1EvidenceRecordDataObjectDigestBuilderFactory() {
        // empty
    }

    @Override
    public DataObjectDigestBuilder create(DSSDocument document) {
        return new ASN1EvidenceRecordDataObjectDigestBuilder(document);
    }

    @Override
    public DataObjectDigestBuilder create(DSSDocument document, DigestAlgorithm digestAlgorithm) {
        return new ASN1EvidenceRecordDataObjectDigestBuilder(document, digestAlgorithm);
    }

}
