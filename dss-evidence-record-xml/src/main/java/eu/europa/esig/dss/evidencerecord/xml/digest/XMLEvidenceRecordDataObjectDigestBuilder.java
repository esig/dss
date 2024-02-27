package eu.europa.esig.dss.evidencerecord.xml.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.digest.AbstractDataObjectDigestBuilder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;

import java.io.IOException;
import java.io.InputStream;

/**
 * Generates digests for data objects to be protected by an IETF RFC 6283 XMLERS evidence-record
 *
 */
public class XMLEvidenceRecordDataObjectDigestBuilder extends AbstractDataObjectDigestBuilder {

    /** Canonicalization method to be used on processing of XML documents */
    private final String canonicalizationMethod;

    /**
     * Constructor to create a builder for computing digest on the given binaries using a SHA-256 digest algorithm and
     * default "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     *
     * @param binaries byte array to compute hash on
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final byte[] binaries) {
        this(binaries, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to create a builder for computing digest on the given InputStream using a SHA-256 digest algorithm and
     * default "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     *
     * @param inputStream {@link InputStream} to compute hash on
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final InputStream inputStream) {
        this(inputStream, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to create a builder for computing digest on the given document using a SHA-256 digest algorithm and
     * default "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     *
     * @param document {@link DSSDocument} to compute hash on
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final DSSDocument document) {
        this(document, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to create a builder for computing digest on the given binaries using a provided digest algorithm and
     * default "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     *
     * @param binaries {@link DigestAlgorithm} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final byte[] binaries, final DigestAlgorithm digestAlgorithm) {
        this(binaries, digestAlgorithm, null);
    }

    /**
     * Constructor to create a builder for computing digest on the given InputStream using a provided digest algorithm and
     * default "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     *
     * @param inputStream {@link InputStream} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final InputStream inputStream, final DigestAlgorithm digestAlgorithm) {
        this(inputStream, digestAlgorithm, null);
    }

    /**
     * Constructor to create a builder for computing digest on the given document using a provided digest algorithm and
     * default "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     *
     * @param document {@link DSSDocument} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final DSSDocument document, final DigestAlgorithm digestAlgorithm) {
        this(document, digestAlgorithm, null);
    }

    /**
     * Constructor to create a builder for computing digest on the given binaries using a provided digest algorithm
     * and canonicalization method
     *
     * @param binaries {@link InputStream} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     * @param canonicalizationMethod {@link String} canonicalization method to be used
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final byte[] binaries, final DigestAlgorithm digestAlgorithm,
                                                    final String canonicalizationMethod) {
        super(binaries, digestAlgorithm);
        this.canonicalizationMethod = canonicalizationMethod;
    }

    /**
     * Constructor to create a builder for computing digest on the given InputStream using a provided digest algorithm
     * and canonicalization method
     *
     * @param inputStream {@link InputStream} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     * @param canonicalizationMethod {@link String} canonicalization method to be used
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final InputStream inputStream, final DigestAlgorithm digestAlgorithm,
                                                    final String canonicalizationMethod) {
        super(inputStream, digestAlgorithm);
        this.canonicalizationMethod = canonicalizationMethod;
    }

    /**
     * Constructor to create a builder for computing digest on the given document using a provided digest algorithm
     * and canonicalization method
     *
     * @param document {@link DSSDocument} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     * @param canonicalizationMethod {@link String} canonicalization method to be used
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final DSSDocument document, final DigestAlgorithm digestAlgorithm,
                                                    final String canonicalizationMethod) {
        super(document, digestAlgorithm);
        this.canonicalizationMethod = canonicalizationMethod;
    }

    @Override
    public Digest build() {
        DSSDocument providedDocument = document;
        if (inputStream != null) {
            providedDocument = new InMemoryDocument(inputStream);
        }
        if (providedDocument == null) {
            throw new IllegalStateException("DSSDocument or InputStream shall be defined!");
        }
        byte[] hashValue;
        if (DomUtils.isDOM(providedDocument)) {
            try (InputStream is = providedDocument.openStream()) {
                byte[] binaries = XMLCanonicalizer.createInstance(canonicalizationMethod).canonicalize(is);
                hashValue = DSSUtils.digest(digestAlgorithm, binaries);
            } catch (IOException e) {
                throw new DSSException(String.format("Unable to read document with name '%s'! Reason : %s", providedDocument.getName(), e.getMessage()), e);
            }
        } else {
            String base64EncodedDigest = providedDocument.getDigest(digestAlgorithm);
            hashValue = Utils.fromBase64(base64EncodedDigest);
        }
        return new Digest(digestAlgorithm, hashValue);
    }

}
