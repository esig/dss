package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.pdf.AnnotationBox;

/**
 * Performs operations on a Font object corresponding the used implementation
 *
 */
public interface DSSFontMetrics {

    /**
     * Returns an array of strings, divided by a new line character
     *
     * @param text {@link String} original text to get lines from
     * @return an array of {@link String}s
     */
    String[] getLines(String text);

    /**
     * Computes a text boundary box
     *
     * @param text {@link String} the original text to get Dimension for
     * @param fontSize the size of a font
     * @param padding the padding between text and its boundaries
     * @return {@link AnnotationBox} of the text
     */
    AnnotationBox computeTextBoundaryBox(String text, float fontSize, float padding);

    /**
     * Computes a width for a string of a given size
     *
     * @param str {@link String} to get width of
     * @param size of a string
     * @return string width
     */
   float getWidth(String str, float size);

    /**
     * Computes a height for a string of a given size
     *
     * @param str {@link String} to get height of
     * @param size of a string
     * @return string width
     */
    float getHeight(String str, float size);

}
