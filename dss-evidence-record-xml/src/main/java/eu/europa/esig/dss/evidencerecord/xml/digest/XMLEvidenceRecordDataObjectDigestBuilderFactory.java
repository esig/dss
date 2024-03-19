package eu.europa.esig.dss.evidencerecord.xml.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilder;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilderFactory;

/**
 * Creates a new instance of {@code eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilder}
 * to compute hashes for RFC 6283 XMLERS evidence records
 *
 */
public class XMLEvidenceRecordDataObjectDigestBuilderFactory implements DataObjectDigestBuilderFactory {

    /** Canonicalization method to be used on processing of XML documents */
    private String canonicalizationMethod;

    /**
     * Default constructor
     */
    public XMLEvidenceRecordDataObjectDigestBuilderFactory() {
        // empty
    }

    /**
     * Sets a canonicalization method to be used
     * Default: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     *
     * @param canonicalizationMethod {@link String}
     * @return this {@link XMLEvidenceRecordDataObjectDigestBuilderFactory}
     */
    public XMLEvidenceRecordDataObjectDigestBuilderFactory setCanonicalizationMethod(String canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
        return this;
    }

    @Override
    public DataObjectDigestBuilder create(DSSDocument document) {
        final XMLEvidenceRecordDataObjectDigestBuilder dataObjectDigestBuilder =
                new XMLEvidenceRecordDataObjectDigestBuilder(document);
        dataObjectDigestBuilder.setCanonicalizationMethod(canonicalizationMethod);
        return dataObjectDigestBuilder;
    }

    @Override
    public DataObjectDigestBuilder create(DSSDocument document, DigestAlgorithm digestAlgorithm) {
        final XMLEvidenceRecordDataObjectDigestBuilder dataObjectDigestBuilder =
                new XMLEvidenceRecordDataObjectDigestBuilder(document, digestAlgorithm);
        dataObjectDigestBuilder.setCanonicalizationMethod(canonicalizationMethod);
        return dataObjectDigestBuilder;
    }

}
