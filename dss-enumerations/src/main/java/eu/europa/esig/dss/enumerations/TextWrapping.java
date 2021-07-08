package eu.europa.esig.dss.enumerations;

/**
 * This enumeration defines a set of possibilities for text wrapping within a signature field with
 * a fixed width and height for a PDF visual signature creation
 *
 */
public enum TextWrapping {

    /**
     * When using the value, a font size is adapted in order to fill the whole signature field's space,
     * by keeping the defined whitespaces in new lines by user
     */
    FILL_BOX,

    /**
     * The text is formatted, by separating the provided text to multiple lines in order to find the biggest font size
     * in order to wrap the text to the defined signature field's box
     */
    FILL_BOX_AND_LINEBREAK,

    /**
     * When using the value, the text is generated based on the font values provided within parameters
     */
    FONT_BASED;

}
