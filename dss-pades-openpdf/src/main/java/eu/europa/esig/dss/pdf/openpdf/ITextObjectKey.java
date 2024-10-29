package eu.europa.esig.dss.pdf.openpdf;

import com.lowagie.text.pdf.PdfIndirectReference;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;

import java.util.Objects;

/**
 * OpenPdf (iText) implementation of a PDF object identifier
 *
 */
public class ITextObjectKey implements PdfObjectKey {

    /** Value identifying the PDF object */
    private final PdfIndirectReference value;

    /**
     * Default constructor
     *
     * @param value {@link PdfIndirectReference}
     */
    public ITextObjectKey(final PdfIndirectReference value) {
        this.value = value;
    }

    @Override
    public PdfIndirectReference getValue() {
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

        ITextObjectKey that = (ITextObjectKey) o;
        return Objects.equals(value.toString(), that.value.toString());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value.toString());
    }

}
