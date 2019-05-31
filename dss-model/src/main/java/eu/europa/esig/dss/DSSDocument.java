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
package eu.europa.esig.dss;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;

/**
 * Interface representing a DSS document.
 *
 */
public interface DSSDocument extends Serializable {

	/**
	 * Opens a {@code InputStream} on the {@code DSSDocument} contents. The type of the {@code InputStream} depends on
	 * the type of the {@code DSSDocument}.
	 *
	 * @return an {@code InputStream}
	 * @throws DSSException
	 *             if any error happens
	 */
	InputStream openStream() throws DSSException;

	/**
	 * Writes the content of the document to the provided OutputStream
	 * 
	 * @param stream
	 *            the output stream where to write
	 * @throws IOException
	 *             if any IO error happens
	 */
	void writeTo(OutputStream stream) throws IOException;

	/**
	 * Returns the name of the document. If the {@code DSSDocument} was built based on the {@code File} then the file
	 * name is returned.
	 *
	 * @return {@code String} representing the name of the current {@code DSSDocument}
	 */
	String getName();

	/**
	 * This method sets the name of the {@code DSSDocument}.
	 *
	 * @param name
	 *            the document name
	 */
	void setName(String name);

	/**
	 * Returns the {@code String} representing the absolute path to the encapsulated document.
	 *
	 * @return {@code String} representing the absolute path to the encapsulated document.
	 */
	String getAbsolutePath();

	/**
	 * Returns the mime-type of the {@code DSSDocument}.
	 *
	 * @return {@code MimeType}
	 */
	MimeType getMimeType();

	/**
	 * This method sets the mime-type of the {@code DSSDocument}.
	 *
	 * @param mimeType
	 *            {@code MimeType}
	 */
	void setMimeType(final MimeType mimeType);

	/**
	 * Save the content of the DSSDocument to the file.
	 *
	 * @param filePath
	 *            the path to the file to be created
	 * @throws IOException
	 *             if any IO error happens
	 */
	void save(final String filePath) throws IOException;

	/**
	 * This method returns the encoded digest value of the current {@code DSSDocument} using the base64 algorithm.
	 *
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm}
	 * @return base64 encoded {@code String}
	 */
	String getDigest(final DigestAlgorithm digestAlgorithm);

}
