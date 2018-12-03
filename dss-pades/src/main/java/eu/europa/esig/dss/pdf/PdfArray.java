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

import java.io.IOException;

/**
 * The usage of this interface permit the user to choose the underlying PDF library use to created PDF signatures.
 */
public interface PdfArray {

	/**
	 * Retrieves the array size
	 * 
	 * @return the size of the current array
	 */
	int size();

	/**
	 * Retrieves the byte array at the position i
	 * 
	 * @param i
	 *          the position
	 * @return the found byte array
	 * @throws IOException
	 */
	byte[] getBytes(int i) throws IOException;

	/**
	 * Retrieves the Object Number for the position i
	 * 
	 * @param i
	 *          the position
	 * @return the object number
	 */
	long getObjectNumber(int i);

	/**
	 * Retrieves the integer at the position i
	 * 
	 * @param i
	 *          the position
	 * @return the found integer
	 * @throws IOException
	 */
	int getInt(int i) throws IOException;

}
