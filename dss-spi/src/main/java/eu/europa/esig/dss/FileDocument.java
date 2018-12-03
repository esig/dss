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

import java.io.File;
import java.io.InputStream;

/**
 * Document implementation stored on file-system.
 *
 */
public class FileDocument extends CommonDocument {

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
		if (file == null) {
			throw new NullPointerException();
		}
		if (!file.exists()) {
			throw new DSSException("File Not Found: " + file.getAbsolutePath());
		}
		this.file = file;
		this.name = file.getName();
		this.mimeType = MimeType.fromFileName(file.getName());
	}

	@Override
	public InputStream openStream() {
		return DSSUtils.toInputStream(file);
	}

	public boolean exists() {
		return file.exists();
	}

	public File getParentFile() {
		return file.getParentFile();
	}

	@Override
	public String getAbsolutePath() {
		return file.getAbsolutePath();
	}

}
