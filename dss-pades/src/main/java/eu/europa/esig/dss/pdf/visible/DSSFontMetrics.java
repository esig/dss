/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
     * @return {@link AnnotationBox} of the text
     */
    AnnotationBox computeTextBoundaryBox(String text, float fontSize);

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
