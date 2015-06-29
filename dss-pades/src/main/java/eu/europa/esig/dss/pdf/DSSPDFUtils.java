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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

import eu.europa.esig.dss.DSSException;

/**
 * This class proposes some utility methods to manipulate PDF files.
 *
 */
public final class DSSPDFUtils {

	private DSSPDFUtils() {
	}

	/**
	 * This method returns the temporary {@code File} with the provided contents.
	 *
	 * @param pdfData {@code InputStream} representing the contents of the returned {@code File}
	 * @return {@code File} with the given contents
	 * @throws DSSException in case of any {@code IOException}
	 */
	public static File getFileFromPdfData(final InputStream pdfData) throws DSSException {

		FileOutputStream fileOutputStream = null;
		try {

			final File file = File.createTempFile("sd-dss-", ".pdf");
			fileOutputStream = new FileOutputStream(file);
			IOUtils.copy(pdfData, fileOutputStream);
			return file;
		} catch (IOException e) {
			throw new DSSException("The process has no rights to write or to access 'java.io.tmpdir': " + System.getProperty("java.io.tmpdir"), e);
		} finally {
			IOUtils.closeQuietly(pdfData);
			IOUtils.closeQuietly(fileOutputStream);
		}
	}

	/**
	 *
	 *
	 * @param toSignFile
	 * @param signedFile
	 * @return
	 * @throws DSSException
	 */
	public static FileOutputStream getFileOutputStream(final File toSignFile, final File signedFile) throws DSSException {

		FileInputStream fileInputStream = null;
		try {

			final FileOutputStream fileOutputStream = new FileOutputStream(signedFile);
			fileInputStream = new FileInputStream(toSignFile);
			IOUtils.copy(fileInputStream, fileOutputStream);
			return fileOutputStream;
		} catch (IOException e) {
			IOUtils.closeQuietly(fileInputStream);
			throw new DSSException(e);
		}
	}

}