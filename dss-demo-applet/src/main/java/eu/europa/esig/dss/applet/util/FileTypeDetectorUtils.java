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
package eu.europa.esig.dss.applet.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import eu.europa.esig.dss.applet.main.FileType;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public final class FileTypeDetectorUtils {
	/**
	 * @param file
	 * @return
	 * @throws IOException
	 */
	private static String extractPreambleString(final File file) throws IOException {

		FileInputStream inputStream = null;

		try {
			inputStream = new FileInputStream(file);

			final byte[] preamble = new byte[5];
			final int read = inputStream.read(preamble);
			if (read < 5) {
				throw new RuntimeException();
			}

			return new String(preamble);
		} finally {
			IOUtils.closeQuietly(inputStream);
		}
	}

	private static boolean isASiCS(final File file) {
		return file.getName().toLowerCase().endsWith(".asics");
	}

	private static boolean isASiCE(final File file) {
		return file.getName().toLowerCase().endsWith(".asice");
	}

	/**
	 * @param file
	 * @return
	 * @throws FileNotFoundException
	 */
	private static boolean isCMS(final File file) throws FileNotFoundException {
		FileInputStream inputStream = null;

		try {
			inputStream = new FileInputStream(file);
			new CMSSignedData(inputStream);
			return true;
		} catch (final CMSException e) {
			return false;
		} finally {
			IOUtils.closeQuietly(inputStream);
		}
	}

	/**
	 * @param preamble
	 * @return
	 */
	private static boolean isPDF(final String preamble) {
		return preamble.equals("%PDF-");
	}

	/**
	 * @param preamble
	 * @return
	 */
	private static boolean isXML(final String preamble) {
		return preamble.equals("<?xml");
	}

	/**
	 * @param file
	 * @return
	 */
	public static FileType resolveFiletype(final File file) {

		try {
			final String preamble = extractPreambleString(file);

			// XML
			if (isXML(preamble)) {
				return FileType.XML;
			}
			// PDF
			if (isPDF(preamble)) {
				return FileType.PDF;
			}

			if (isASiCS(file)) {
				return FileType.ASiCS;
			}

			if (isASiCE(file)) {
				return FileType.ASiCE;
			}

			try {
				if (isCMS(file)) {
					return FileType.CMS;
				}
				return FileType.BINARY;
			} catch (final Exception e) {
				return FileType.BINARY;
			}

		} catch (final IOException e) {
			throw new RuntimeException("Cannot determine the mime/type", e);
		}
	}

	/**
	 * The default constructor for FileTypeDetectorUtils.
	 */
	private FileTypeDetectorUtils() {

	}
}
