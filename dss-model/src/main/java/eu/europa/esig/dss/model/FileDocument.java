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
package eu.europa.esig.dss.model;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Document implementation stored on file-system.
 *
 */
@SuppressWarnings("serial")
public class FileDocument extends CommonDocument {

	/** The file */
	private final File file;

	/**
	 * Create a FileDocument
	 *
	 * @param path
	 *            the path to the file
	 */
	public FileDocument(final String path) {
		this(new File(path));
	}

	/**
	 * Create a FileDocument
	 *
	 * @param file
	 *            {@code File}
	 */
	public FileDocument(final File file) {
		Objects.requireNonNull(file, "File cannot be null");
		if (!file.exists()) {
			throw new DSSException("File Not Found: " + file.getAbsolutePath());
		}
		this.file = file;
		this.name = file.getName();
		this.mimeType = MimeType.fromFileName(file.getName());
	}

	@Override
	public InputStream openStream() {
		try {
			return new FileInputStream(file);
		} catch (FileNotFoundException e) {
			throw new DSSException("Unable to create a FileInputStream", e);
		}
	}

	/**
	 * Checks if the file exists
	 *
	 * @return TRUE if the file exists in the file system, FALSE otherwise
	 */
	public boolean exists() {
		return file.exists();
	}

	/**
	 * Gets the {@code File}
	 *
	 * @return {@link File}
	 */
	public File getFile() {
		return file;
	}

	@Override
	public String getAbsolutePath() {
		return file.getAbsolutePath();
	}

}
