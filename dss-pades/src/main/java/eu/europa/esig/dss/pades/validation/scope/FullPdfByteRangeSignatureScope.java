package eu.europa.esig.dss.pades.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.pades.validation.ByteRange;

/**
 * Represents a FULL Pdf signature scope (signature/timestamp covers a complete PDF file)
 *
 */
public class FullPdfByteRangeSignatureScope extends PdfByteRangeSignatureScope {

    /** A string used for a fully covered PDF representation */
    private static final String FULL_PDF = "Full PDF";

    /**
     * Default constructor
     *
     * @param byteRange {@link ByteRange} used byte range
     * @param digest {@link Digest} of the signed byte range
     */
    public FullPdfByteRangeSignatureScope(final ByteRange byteRange, final Digest digest) {
        super(FULL_PDF, byteRange, digest);
    }

    @Override
    public SignatureScopeType getType() {
        return SignatureScopeType.FULL;
    }

}
