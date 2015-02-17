/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * Interface representing a DSS document.
 *
 */
public interface DSSDocument extends Serializable {

	/**
	 * Opens a {@code InputStream} on the {@code DSSDocument} contents. The type of the {@code InputStream} depends on the type of the {@code DSSDocument}. The stream must be
	 * closed in case of the {@code FileDocument}.
	 *
	 * @return an {@code InputStream}
	 * @throws DSSException
	 */
	public InputStream openStream() throws DSSException;

	/**
	 * Returns the array of bytes representing the document. Do not use this method with large files.
	 *
	 * @return array of {@code byte}
	 */
	public byte[] getBytes() throws DSSException;

	/**
	 * Returns the name of the document. If the {@code DSSDocument} was built based on the {@code File} then the file name is returned.
	 *
	 * @return {@code String}  representing the name of the current {@code DSSDocument}
	 */
	public String getName();

	/**
	 * Returns the {@code String} representing the absolute path to the encapsulated document.
	 *
	 * @return {@code String} representing the absolute path to the encapsulated document.
	 */
	public String getAbsolutePath();

	/**
	 * Returns the mime-type of the {@code DSSDocument}.
	 *
	 * @return {@code MimeType}
	 */
	public MimeType getMimeType();

	/**
	 * This method sets the mime-type of the {@code DSSDocument}.
	 *
	 * @param mimeType {@code MimeType}
	 */
	public void setMimeType(final MimeType mimeType);

	/**
	 * Save the content of the DSSDocument to the file.
	 *
	 * @param filePath the path to the file to be created
	 */
	public void save(final String filePath) throws IOException;

	/**
	 * This method returns the encoded digest value of the current {@code DSSDocument} using the base64 algorithm.
	 *
	 * @param digestAlgorithm {@code DigestAlgorithm}
	 * @return base64 encoded {@code String}
	 */
	public String getDigest(final DigestAlgorithm digestAlgorithm);

	/**
	 * This method return the next {@code DSSDocument}.
	 *
	 * @return {@code DSSDocument}
	 */
	public DSSDocument getNextDocument();

	public void setNextDocument(final DSSDocument nextDocument);
}
