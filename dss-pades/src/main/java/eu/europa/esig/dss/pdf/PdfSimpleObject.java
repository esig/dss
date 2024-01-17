package eu.europa.esig.dss.pdf;

/**
 * Represents a wrapper for a simple value (Integer, String, etc.), extracted from a PDF
 *
 */
public class PdfSimpleObject implements PdfObject {

    /** Value of the object */
    private final Object value;

    /** Parent of the object */
    private final PdfObject parent;

    /**
     * Default constructor
     */
    public PdfSimpleObject(final Object value) {
        this(value, null);
    }

    /**
     * Constructor with a parent
     *
     * @param value {@link Object} embedded value of the current PDF object
     * @param parent {@link PdfObject}
     */
    public PdfSimpleObject(final Object value, final PdfObject parent) {
        this.value = value;
        this.parent = parent;
    }

    @Override
    public Object getValue() {
        return value;
    }

    @Override
    public PdfObject getParent() {
        return parent;
    }

}
