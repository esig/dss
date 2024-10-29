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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.pades.validation.PdfObjectKey;

import java.io.IOException;

/**
 * The usage of this interface permit the user to choose the underlying PDF library use to created PDF signatures.
 */
public interface PdfArray extends PdfObject {

	/**
	 * Retrieves the array size
	 * 
	 * @return the size of the current array
	 */
	int size();

	/**
	 * Retrieves the stream byte array at the position i
	 * 
	 * @param i
	 *          the position
	 * @return the found stream byte array
	 * @throws IOException if an exception occurs
	 */
	byte[] getStreamBytes(int i) throws IOException;

	/**
	 * Retrieves the Object Number for the position i
	 * 
	 * @param i
	 *          the position
	 * @return the object number
	 * @deprecated since DSS 6.2. Please use {@code #getObjectKey} method instead
	 */
	@Deprecated
	Long getObjectNumber(int i);

	/**
	 * Retrieves the Object key for the position i
	 *
	 * @param i
	 *          the position
	 * @return {@link eu.europa.esig.dss.pades.validation.PdfObjectKey}
	 */
	PdfObjectKey getObjectKey(int i);

	/**
	 * Retrieves the number at the position i
	 * 
	 * @param i
	 *          the position
	 * @return the found number
	 */
	Number getNumber(int i);

	/**
	 * Returns a String entry at the position i
	 *
	 * @param i
	 *          the position
	 * @return {@link String}
	 */
	String getString(int i);

	/**
	 * Returns a dictionary entry at the position i
	 *
	 * @param i
	 *          the position
	 * @return {@link PdfDict}
	 */
	PdfDict getAsDict(int i);

	/**
	 * Returns an object entry at the position i
	 *
	 * @param i
	 *          the position
	 * @return {@link PdfObject}
	 */
	PdfObject getObject(int i);

	/**
	 * Adds {@code pdfObject}
	 *
	 * @param pdfObject {@link PdfObject}
	 */
	void addObject(PdfObject pdfObject);

	/**
	 * Sets whether the array shall be written directly to its parent
	 *
	 * @param direct whether the array shall be written directly
	 */
	void setDirect(boolean direct);

}
