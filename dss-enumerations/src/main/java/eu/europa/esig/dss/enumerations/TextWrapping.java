/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
