package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import org.apache.pdfbox.cos.COSObjectKey;

import java.util.Objects;

/**
 * PdfBox implementation of the PDF object key
 *
 */
public class PdfBoxObjectKey implements PdfObjectKey {

    /** Object representing a unique PDFBox identifier */
    private final COSObjectKey value;

    /**
     * Default constructor
     *
     * @param value {@link COSObjectKey} key value
     */
    public PdfBoxObjectKey(final COSObjectKey value) {
        this.value = value;
    }

    @Override
    public COSObjectKey getValue() {
        return value;
    }

    @Override
    public long getNumber() {
        return value.getNumber();
    }

    @Override
    public int getGeneration() {
        return value.getGeneration();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PdfBoxObjectKey objectKey = (PdfBoxObjectKey) o;
        return Objects.equals(value, objectKey.value);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }

}
