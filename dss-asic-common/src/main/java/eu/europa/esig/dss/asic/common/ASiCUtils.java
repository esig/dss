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
package eu.europa.esig.dss.asic.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;

public final class ASiCUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCUtils.class);

	public static final String MIME_TYPE = "mimetype";
	public static final String MIME_TYPE_COMMENT = MIME_TYPE + "=";
	public static final String META_INF_FOLDER = "META-INF/";
	public static final String PACKAGE_ZIP = "package.zip";

    /**
     * Minimum file size to be analized on zip bombing
     */
	private static final long ZIP_ENTRY_THRESHOLD = 1000000; // 1 MB
	
    /**
     * Maximum compression ratio.
     */
	private static final long ZIP_ENTRY_RATIO = 50;
	
    /**
	 * Max iteration over the zip entries
	 */
	private static final int MAX_MALFORMED_FILES = 100;

	private ASiCUtils() {
	}

	public static boolean isSignature(final String entryName) {
		return entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature") && !entryName.contains("Manifest");
	}

	public static String getMimeTypeString(final ASiCParameters asicParameters) {
		final String asicParameterMimeType = asicParameters.getMimeType();
		String mimeTypeString;
		if (Utils.isStringBlank(asicParameterMimeType)) {
			if (isASiCE(asicParameters)) {
				mimeTypeString = MimeType.ASICE.getMimeTypeString();
			} else {
				mimeTypeString = MimeType.ASICS.getMimeTypeString();
			}
		} else {
			mimeTypeString = asicParameterMimeType;
		}
		return mimeTypeString;
	}

	public static boolean isASiCMimeType(final MimeType asicMimeType) {
		return MimeType.ASICS.equals(asicMimeType) || MimeType.ASICE.equals(asicMimeType) || MimeType.ODT.equals(asicMimeType)
				|| MimeType.ODS.equals(asicMimeType);
	}

	public static ASiCContainerType getASiCContainerType(final MimeType asicMimeType) {
		if (MimeType.ASICS.equals(asicMimeType)) {
			return ASiCContainerType.ASiC_S;
		} else if (MimeType.ASICE.equals(asicMimeType) || MimeType.ODT.equals(asicMimeType) || MimeType.ODS.equals(asicMimeType)) {
			return ASiCContainerType.ASiC_E;
		} else {
			throw new IllegalArgumentException("Not allowed mimetype '" + asicMimeType.getMimeTypeString() + "'");
		}
	}

	public static boolean isASiCE(final ASiCParameters asicParameters) {
		return ASiCContainerType.ASiC_E.equals(asicParameters.getContainerType());
	}

	public static boolean isASiCS(final ASiCParameters asicParameters) {
		return ASiCContainerType.ASiC_S.equals(asicParameters.getContainerType());
	}

	public static MimeType getMimeType(ASiCParameters asicParameters) {
		return isASiCE(asicParameters) ? MimeType.ASICE : MimeType.ASICS;
	}

	public static boolean isArchiveContainsCorrectSignatureFileWithExtension(DSSDocument toSignDocument, String extension) {
		List<String> filenames = getFileNames(toSignDocument);
		for (String filename : filenames) {
			if (isSignature(filename) && filename.endsWith(extension)) {
				return true;
			}
		}
		return false;
	}

	public static boolean isArchive(List<DSSDocument> docs) {
		if (Utils.collectionSize(docs) == 1) {
			return isASiCContainer(docs.get(0));
		}
		return false;
	}

	public static boolean isASiCContainer(DSSDocument dssDocument) {
		if (dssDocument == null) {
			return false;
		}
		byte[] preamble = new byte[2];
		try (InputStream is = dssDocument.openStream()) {
			int r = is.read(preamble, 0, 2);
			if (r != 2) {
				return false;
			}
		} catch (IOException e) {
			throw new DSSException("Unable to read the 2 first bytes", e);
		}

		return (preamble[0] == 'P') && (preamble[1] == 'K');
	}

	public static boolean isXAdES(final String entryName) {
		return isSignature(entryName) && entryName.endsWith(".xml");
	}

	public static boolean isCAdES(final String entryName) {
		return isSignature(entryName) && (entryName.endsWith(".p7s"));
	}

	public static boolean isOpenDocument(final DSSDocument mimeTypeDocument) {
		MimeType mimeType = ASiCUtils.getMimeType(mimeTypeDocument);
		return MimeType.ODS == mimeType || MimeType.ODT == mimeType;
	}

	public static MimeType getMimeType(final DSSDocument mimeTypeDocument) {
		if (mimeTypeDocument == null) {
			return null;
		}
		try (InputStream is = mimeTypeDocument.openStream()) {
			byte[] byteArray = Utils.toByteArray(is);
			final String mimeTypeString = new String(byteArray, "UTF-8");
			return MimeType.fromMimeTypeString(mimeTypeString);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static ASiCContainerType getContainerType(DSSDocument archive, DSSDocument mimetype, String zipComment, List<DSSDocument> signedDocuments) {
		ASiCContainerType containerType = getContainerTypeFromMimeType(archive.getMimeType());
		if (containerType == null) {
			containerType = getContainerTypeFromMimeTypeDocument(mimetype);
			if (containerType == null) {
				containerType = getContainerTypeFromZipComment(zipComment);
			}
		}

		if (containerType == null) {
			LOG.warn("Unable to define the ASiC Container type with its properties");
			if (Utils.collectionSize(signedDocuments) == 1) {
				containerType = ASiCContainerType.ASiC_S;
			} else if (Utils.collectionSize(signedDocuments) > 1) {
				containerType = ASiCContainerType.ASiC_E;
			} else {
				throw new DSSException("The provided file does not contain signed documents. The signature validation is not possible");
			}
		}

		return containerType;
	}

	private static ASiCContainerType getContainerTypeFromZipComment(String zipComment) {
		if (Utils.isStringNotBlank(zipComment)) {
			int indexOf = zipComment.indexOf(MIME_TYPE_COMMENT);
			if (indexOf > -1) {
				String asicCommentMimeTypeString = zipComment.substring(MIME_TYPE_COMMENT.length() + indexOf);
				MimeType mimeTypeFromZipComment = MimeType.fromMimeTypeString(asicCommentMimeTypeString);
				return getContainerTypeFromMimeType(mimeTypeFromZipComment);
			}
		}
		return null;
	}

	private static ASiCContainerType getContainerTypeFromMimeTypeDocument(DSSDocument mimetype) {
		if (mimetype != null) {
			MimeType mimeTypeFromEmbeddedFile = ASiCUtils.getMimeType(mimetype);
			return getContainerTypeFromMimeType(mimeTypeFromEmbeddedFile);
		}
		return null;
	}

	private static ASiCContainerType getContainerTypeFromMimeType(MimeType mimeType) {
		if (ASiCUtils.isASiCMimeType(mimeType)) {
			return ASiCUtils.getASiCContainerType(mimeType);
		}
		return null;
	}

	/**
	 * Transforms {@code num} with the pattern:
	 *     {@code "2 -> 002"}, {@code "10 -> 010"}, etc.
	 * @param num
	 * @return {@link String}
	 */
	public static String getPadNumber(int num) {
		String numStr = String.valueOf(num);
		String zeroPad = "000";
		return zeroPad.substring(numStr.length()) + numStr;
	}

	public static boolean isAsic(List<DSSDocument> documents) {
		if (ASiCUtils.isArchive(documents)) {
			DSSDocument archive = documents.get(0);
			boolean cades = ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(archive, "p7s");
			boolean xades = ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(archive, "xml");
			return cades || xades;
		}

		return false;
	}
	
	/**
	 * Reads and copies InputStream in a secure way, depending on the provided container size
	 * This method allows to detect "ZipBombing" (large files inside a zip container)
	 * @param is {@link InputStream} of file
	 * @param os {@link OutputStream} where save file to
	 * @param containerSize - zip container size
	 */
	public static void secureCopy(InputStream is, OutputStream os, long containerSize) throws IOException {
		byte[] data = new byte[2048];
		int nRead;
	    int byteCounter = 0;
	    long allowedSize = containerSize * ZIP_ENTRY_RATIO;
	    while ((nRead = is.read(data)) != -1) {
	    	byteCounter += nRead;
	    	if (byteCounter > ZIP_ENTRY_THRESHOLD && byteCounter > allowedSize) {
	    		throw new DSSException("Zip Bomb detected in the ZIP container. Validation is interrupted.");
	    	}
	    	os.write(data, 0, nRead);
	    }
	}

	/**
	 * Returns the file names for the given archive
	 * 
	 * @param archive
	 *                the archive to be analyzed
	 * @return a list of filename
	 */
	public static List<String> getFileNames(DSSDocument archive) {
		List<String> filenames = new ArrayList<String>();
		try (InputStream is = archive.openStream(); ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry entry;
			while ((entry = getNextValidEntry(zis)) != null) {
				filenames.add(entry.getName());
			}
		} catch (IOException e) {
			throw new DSSException("Unable to retrieve filenames", e);
		}
		return filenames;
	}

	/**
	 * Returns the next entry from the given ZipInputStream by skipping corrupted or
	 * not accessible files NOTE: returns null only when the end of ZipInputStream
	 * is reached
	 * 
	 * @param zis {@link ZipInputStream} to get next entry from
	 * @return list of file name {@link String}s
	 * @throws DSSException if too much tries failed
	 */
	public static ZipEntry getNextValidEntry(ZipInputStream zis) {
		int counter = 0;
		while (counter < MAX_MALFORMED_FILES) {
			try {
				return zis.getNextEntry();
			} catch (Exception e) {
				LOG.warn("ZIP container contains a malformed, corrupted or not accessible entry! The entry is skipped. Reason: [{}]", e.getMessage());
				// skip the entry and continue until find the next valid entry or end of the
				// stream
				counter++;
				closeEntry(zis);
			}
		}
		throw new DSSException("Unable to retrieve a valid ZipEntry (" + MAX_MALFORMED_FILES + " tries)");
	}

	/**
	 * Returns file from the given ZipInputStream
	 * 
	 * @param filepath
	 *                      {@link String} filepath where the file is located
	 * @param zis
	 *                      {@link ZipInputStream} of the file
	 * @param containerSize
	 *                      - long byte size of the parent container
	 * @return {@link DSSDocument} created from the given {@code zis}
	 * @throws IOException
	 *                     in case of ZipInputStream read error
	 */
	public static DSSDocument getCurrentDocument(String filepath, ZipInputStream zis, long containerSize) throws IOException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
		    secureCopy(zis, baos, containerSize);
			baos.flush();
			return new InMemoryDocument(baos.toByteArray(), filepath);
		}
	}
	
	/**
	 * This method closes the current Zip Entry. If an error occurs, a
	 * {@link DSSException} is thrown.
	 * 
	 * @param zis
	 *            the {@link ZipInputStream}
	 */
	public static void closeEntry(ZipInputStream zis) {
		try {
			zis.closeEntry();
		} catch (IOException e) {
			throw new DSSException("Unable to close entry", e);
		}
	}

}
