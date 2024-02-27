package eu.europa.esig.dss.evidencerecord.common.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.io.InputStream;
import java.util.Objects;

/**
 * Abstract implementation of {@code DataObjectDigestBuilder}
 *
 */
public abstract class AbstractDataObjectDigestBuilder implements DataObjectDigestBuilder {

    /**
     * InputStream to compute digest on
     */
    protected final InputStream inputStream;

    /**
     * Document to compute digest on
     */
    protected final DSSDocument document;

    /**
     * The digest algorithm to be used on hash computation
     */
    protected final DigestAlgorithm digestAlgorithm;

    /**
     * Constructor to create a builder for computing digest on the given binaries using a SHA-256 digest algorithm
     *
     * @param binaries byte array to compute hash on
     */
    protected AbstractDataObjectDigestBuilder(final byte[] binaries) {
        this(binaries, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to create a builder for computing digest on the given InputStream using a SHA-256 digest algorithm
     *
     * @param inputStream {@link InputStream} to compute hash on
     */
    protected AbstractDataObjectDigestBuilder(final InputStream inputStream) {
        this(inputStream, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to create a builder for computing digest on the given document using a SHA-256 digest algorithm
     *
     * @param document {@link DSSDocument} to compute hash on
     */
    protected AbstractDataObjectDigestBuilder(final DSSDocument document) {
        this(document, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to create a builder for computing digest on the given binaries using a provided digest algorithm
     *
     * @param binaries byte array to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    protected AbstractDataObjectDigestBuilder(final byte[] binaries, final DigestAlgorithm digestAlgorithm) {
        this(new InMemoryDocument(binaries), digestAlgorithm);
    }

    /**
     * Constructor to create a builder for computing digest on the given InputStream using a provided digest algorithm
     *
     * @param inputStream {@link InputStream} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    protected AbstractDataObjectDigestBuilder(final InputStream inputStream, final DigestAlgorithm digestAlgorithm) {
        Objects.requireNonNull(inputStream, "InputStream cannot be null!");
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
        this.document = null;
        this.inputStream = inputStream;
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Constructor to create a builder for computing digest on the given document using a provided digest algorithm
     *
     * @param document {@link DSSDocument} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    protected AbstractDataObjectDigestBuilder(final DSSDocument document, final DigestAlgorithm digestAlgorithm) {
        Objects.requireNonNull(document, "Document cannot be null!");
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
        this.document = document;
        this.inputStream = null;
        this.digestAlgorithm = digestAlgorithm;
    }

    @Override
    public Digest build() {
        byte[] hashValue;
        if (document != null) {
            String base64EncodedDigest = document.getDigest(digestAlgorithm);
            hashValue = Utils.fromBase64(base64EncodedDigest);
        } else if (inputStream != null) {
            hashValue = DSSUtils.digest(digestAlgorithm, inputStream);
        } else {
            throw new IllegalStateException("DSSDocument or InputStream shall be defined!");
        }
        return new Digest(digestAlgorithm, hashValue);
    }

}
