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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.pades.validation.PdfObjectKey;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

/**
 * The usage of this interface permit the user to choose the underlying PDF
 * library use to created PDF signatures.
 */
public interface PdfDict extends PdfObject {

	/**
	 * Gets an embedded dictionary by name
	 *
	 * @param name {@link String} of a dictionary to extract
	 * @return {@link PdfDict}
	 */
	PdfDict getAsDict(String name);

	/**
	 * Gets the pdfArray by name
	 *
	 * @param name {@link String}
	 * @return {@link PdfArray}
	 */
	PdfArray getAsArray(String name);

	/**
	 * Gets binaries by dictionary name
	 *
	 * @param name {@link String}
	 * @return byte array
	 * @throws IOException if an exception occurs
	 */
	byte[] getBinariesValue(String name) throws IOException;

	/**
	 * Lists all encapsulated dictionary names
	 *
	 * @return an array of {@link String}s
	 */
	String[] list();

	/**
	 * Gets a string value by property name
	 *
	 * @param name {@link String} property name
	 * @return {@link String} value
	 */
	String getStringValue(String name);

	/**
	 * Gets a name of the dictionary
	 *
	 * @param name {@link String} property name
	 * @return {@link String} value
	 */
	String getNameValue(String name);

	/**
	 * Gets a date
	 *
	 * @param name {@link String} property name
	 * @return {@link String} value
	 */
	Date getDateValue(String name);

	/**
	 * Returns a number value
	 *
	 * @param name {@link String} property name
	 * @return {@link Number} value
	 */
	Number getNumberValue(String name);

	/**
	 * Returns a PDF object
	 *
	 * @param name {@link String} property name
	 * @return {@link PdfObject} value
	 */
	PdfObject getObject(String name);

	/**
	 * Returns a number of indirect reference to an object, when applicable
	 *
	 * @param name {@link String} property name
	 * @return {@link Object} value
	 * @deprecated since DSS 6.2. Please use {@code #getObjectKey} method instead
	 */
	@Deprecated
	Long getObjectNumber(String name);

	/**
	 * Returns a Pdf object ket of indirect reference to an object, when applicable
	 *
	 * @param name {@link String} property name
	 * @return {@link PdfObjectKey}
	 */
	PdfObjectKey getObjectKey(String name);

	/**
	 * Returns object's stream binaries, when available
	 *
	 * @return byte array
	 * @throws IOException if a stream reading exception occurs
	 */
	byte[] getStreamBytes() throws IOException;

	/**
	 * Creates a new raw input stream.
	 * NOTE: contains raw and not encoded data.
	 *
	 * @return {@link InputStream}
	 * @throws IOException if a stream reading exception occurs
	 */
	InputStream createRawInputStream() throws IOException;

	/**
	 * Returns a size of the raw stream, if present
	 *
	 * @return size of the raw stream, -1 if not applicable
	 * @throws IOException if a stream reading exception occurs
	 */
	long getRawStreamSize() throws IOException;

	/**
	 * Sets the Dictionary {@code pdfObject} with the given {@code key}
	 *
	 * @param key {@link String}
	 * @param pdfObject {@link PdfObject}
	 */
	void setPdfObjectValue(String key, PdfObject pdfObject);

	/**
	 * Sets the Name {@code value} with the given {@code key}
	 *
	 * @param key {@link String}
	 * @param value {@link String}
	 */
	void setNameValue(String key, String value);

	/**
	 * Sets the String {@code value} with the given {@code key}
	 *
	 * @param key {@link String}
	 * @param value {@link String}
	 */
	void setStringValue(String key, String value);

	/**
	 * Sets the Integer {@code value} with the given {@code key}
	 *
	 * @param key {@link String}
	 * @param value {@link Integer}
	 */
	void setIntegerValue(String key, Integer value);

	/**
	 * Sets whether the object shall be written directly to its parent
	 *
	 * @param direct whether the object shall be written directly
	 */
	void setDirect(boolean direct);

	/**
	 * This method verifies if the content of the {@code pdfDict} matches
	 * the corresponding attributes of the current dictionary.
	 * NOTE: this method is different from {@code #equals}, as it does not ensure full equality.
	 *
	 * @param pdfDict {@link PdfDict} to compare
	 * @return TRUE if the content of pdfDict matches, FALSE otherwise
	 */
	boolean match(PdfDict pdfDict);

}
