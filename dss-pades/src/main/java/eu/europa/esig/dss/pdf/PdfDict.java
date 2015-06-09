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
import java.util.Calendar;

/**
 * The usage of this interface permit the user to choose the underlying PDF
 * library use to created PDF signatures.
 */
public interface PdfDict {

	PdfDict getAsDict(String name);

	PdfArray getAsArray(String name);

	boolean hasAName(String name);

	/**
	 * Check if the dictionary contains a name with a specific (PDF Name) value
	 *
	 * @param name
	 * @param value
	 * @return
	 */
	boolean hasANameWithValue(String name, String value);

	byte[] get(String name) throws IOException;

	String[] list();

	void add(String key, PdfArray array);

	void add(String key, PdfStreamArray array);

	void add(String key, PdfDict dict);

	void add(String key, Calendar cal);
}