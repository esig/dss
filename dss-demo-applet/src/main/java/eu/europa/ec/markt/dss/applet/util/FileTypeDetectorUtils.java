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

package eu.europa.ec.markt.dss.applet.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.applet.main.FileType;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
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
			DSSUtils.closeQuietly(inputStream);
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
			DSSUtils.closeQuietly(inputStream);
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
