package eu.europa.esig.dss.pades.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.pades.validation.ByteRange;

/**
 * Represents a partial PDF signature scope, when a signature/timestamp's byte range does not cover the whole document
 *
 */
public class PartialPdfByteRangeSignatureScope extends PdfByteRangeSignatureScope {

    /** A string used for a partially covered PDF representation */
    private static final String PARTIAL_PDF = "Partial PDF";

    /**
     * Default constructor
     *
     * @param byteRange {@link ByteRange} used byte range
     * @param digest {@link Digest} of the signed byte range
     */
    public PartialPdfByteRangeSignatureScope(final ByteRange byteRange, final Digest digest) {
        super(PARTIAL_PDF, byteRange, digest);
    }

    @Override
    public SignatureScopeType getType() {
        return SignatureScopeType.PARTIAL;
    }

}
