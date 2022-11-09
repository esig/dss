package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSDocument;

import java.io.InputStream;

/**
 * Internal representation of a PDF document. Used to reduce memory overloading during the execution.
 *
 */
public class PdfByteRangeDocument extends CommonDocument {

    private static final long serialVersionUID = 7879399189697068569L;

    /** Input PDF document to read */
    private final DSSDocument pdfDocument;

    /** The ByteRange to be read */
    private final ByteRange byteRange;

    /**
     * Default constructor
     *
     * @param pdfDocument {@link DSSDocument} input PDF document to read
     * @param byteRange {@link ByteRange} of the revision to be read
     */
    public PdfByteRangeDocument(final DSSDocument pdfDocument, final ByteRange byteRange) {
        this.pdfDocument = pdfDocument;
        this.byteRange = byteRange;
    }

    /**
     * Returns the {@code ByteRange} of the document
     *
     * @return {@link ByteRange}
     */
    public ByteRange getByteRange() {
        return byteRange;
    }

    @Override
    public InputStream openStream() {
        return new ByteRangeInputStream(pdfDocument.openStream(), byteRange);
    }

}
