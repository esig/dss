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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public final class ASiCUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCUtils.class);

	public static final String MANIFEST_FILENAME = "Manifest";
	public static final String MIME_TYPE = "mimetype";
	public static final String MIME_TYPE_COMMENT = MIME_TYPE + "=";
	public static final String META_INF_FOLDER = "META-INF/";
	public static final String PACKAGE_ZIP = "package.zip";
	public static final String SIGNATURE_FILENAME = "signature";
	public static final String TIMESTAMP_FILENAME = "timestamp";
	public static final String TST_EXTENSION = ".tst";
	public static final String XML_EXTENSION = ".xml";

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

	/**
	 * Verifies if the {@code entryName} represents a signature file name
	 * 
	 * @param entryName {@link String} name to check
	 * @return TRUE if the entryName represents a signature file name, FALSE otherwise
	 */
	public static boolean isSignature(final String entryName) {
		return entryName.startsWith(META_INF_FOLDER) && entryName.contains(SIGNATURE_FILENAME) && !entryName.contains(MANIFEST_FILENAME);
	}

	/**
	 * Verifies if the {@code entryName} represents a timestamp file name
	 * 
	 * @param entryName {@link String} name to check
	 * @return TRUE if the entryName represents a timestamp file name, FALSE otherwise
	 */
	public static boolean isTimestamp(final String entryName) {
		return entryName.startsWith(META_INF_FOLDER) && entryName.contains(TIMESTAMP_FILENAME) && entryName.endsWith(TST_EXTENSION);
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
		return MimeType.ASICS.equals(asicMimeType) || MimeType.ASICE.equals(asicMimeType);
	}

	public static boolean isOpenDocumentMimeType(final MimeType mimeType) {
		return MimeType.ODT.equals(mimeType) || MimeType.ODS.equals(mimeType) || MimeType.ODG.equals(mimeType) || MimeType.ODP.equals(mimeType);
	}

	public static ASiCContainerType getASiCContainerType(final MimeType asicMimeType) {
		if (MimeType.ASICS.equals(asicMimeType)) {
			return ASiCContainerType.ASiC_S;
		} else if (MimeType.ASICE.equals(asicMimeType) || isOpenDocumentMimeType(asicMimeType)) {
			return ASiCContainerType.ASiC_E;
		} else {
			throw new IllegalArgumentException("Not allowed mimetype '" + asicMimeType.getMimeTypeString() + "'");
		}
	}

	public static boolean isASiCE(final ASiCParameters asicParameters) {
		Objects.requireNonNull(asicParameters.getContainerType(), "ASiCContainerType must be defined!");
		return ASiCContainerType.ASiC_E.equals(asicParameters.getContainerType());
	}

	public static boolean isASiCS(final ASiCParameters asicParameters) {
		Objects.requireNonNull(asicParameters.getContainerType(), "ASiCContainerType must be defined!");
		return ASiCContainerType.ASiC_S.equals(asicParameters.getContainerType());
	}

	public static MimeType getMimeType(ASiCParameters asicParameters) {
		return isASiCE(asicParameters) ? MimeType.ASICE : MimeType.ASICS;
	}
	
	/**
	 * Checks if the container contains a signature with the expected {@code extension}
	 * 
	 * @param container {@link DSSDocument} representing an ASiC container
	 * @param extension {@link String} signature file extension to find
	 * @return TRUE if the container contains the expected signature file, FALSE otherwise
	 */
	public static boolean isArchiveContainsCorrectSignatureFileWithExtension(DSSDocument container, String extension) {
		List<String> filenames = getFileNames(container);
		for (String filename : filenames) {
			if (isSignature(filename) && filename.endsWith(extension)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if the container contains a timestamp
	 * 
	 * @param container {@link DSSDocument} representing an ASiC container
	 * @return TRUE if the container contains the expected timestamp file, FALSE otherwise
	 */
	public static boolean isArchiveContainsCorrectTimestamp(DSSDocument container) {
		List<String> filenames = getFileNames(container);
		for (String filename : filenames) {
			if (isTimestamp(filename)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if the {@code document} is a ZIP container
	 * 
	 * @param document {@link DSSDocument} to check
	 * @return TRUE if the {@code DSSDocument} is a ZIP container, FALSE otherwise
	 */
	public static boolean isZip(DSSDocument document) {
		if (document == null) {
			return false;
		}
		byte[] preamble = new byte[2];
		try (InputStream is = document.openStream()) {
			int r = is.read(preamble, 0, 2);
			if (r != 2) {
				return false;
			}
		} catch (IOException e) {
			throw new DSSException("Unable to read the 2 first bytes", e);
		}

		return (preamble[0] == 'P') && (preamble[1] == 'K');
	}
	
	public static boolean isASiCWithCAdES(DSSDocument archive) {
		return isArchiveContainsCorrectSignatureFileWithExtension(archive, ".p7s") || isArchiveContainsCorrectTimestamp(archive);
	}

	public static boolean isXAdES(final String entryName) {
		return isSignature(entryName) && entryName.endsWith(".xml");
	}

	public static boolean isCAdES(final String entryName) {
		return isSignature(entryName) && (entryName.endsWith(".p7s"));
	}

	public static boolean isOpenDocument(final DSSDocument mimeTypeDoc) {
		MimeType mimeType = getMimeType(mimeTypeDoc);
		if (mimeTypeDoc != null) {
			return isOpenDocumentMimeType(mimeType);
		}
		return false;
	}

	public static MimeType getMimeType(final DSSDocument mimeTypeDocument) {
		if (mimeTypeDocument == null) {
			return null;
		}
		try (InputStream is = mimeTypeDocument.openStream()) {
			byte[] byteArray = Utils.toByteArray(is);
			final String mimeTypeString = new String(byteArray, StandardCharsets.UTF_8);
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

	/**
	 * Checks if the {@code document} is an ASiC container
	 * 
	 * @param document {@link DSSDocument} to check
	 * @return TRUE if the document is an ASiC container, FALSE otherwise
	 */
	public static boolean isAsic(DSSDocument document) {
		if (isZip(document)) {
			boolean cades = ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(document, "p7s");
			boolean xades = ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(document, "xml");
			boolean timestamp = ASiCUtils.isArchiveContainsCorrectTimestamp(document);
			return cades || xades || timestamp;
		}
		return false;
	}
	
	public static boolean isArchiveManifest(String fileName) {
		return fileName.contains("ASiCArchiveManifest") && fileName.endsWith(".xml");
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
		List<String> filenames = new ArrayList<>();
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
	
	/**
	 * Generates an unique name for a new ASiC-E Manifest file, avoiding any name collision
	 * @param expectedManifestName {@link String} defines the expected name of the file without extension (e.g. "ASiCmanifest")
	 * @param existingManifests list of existing {@link DSSDocument} manifests of the type present in the container
	 * @return {@link String} new manifest name
	 */
	public static String getNextASiCEManifestName(final String expectedManifestName, final List<DSSDocument> existingManifests) {
		List<String> manifestNames = getDSSDocumentNames(existingManifests);
		
		String manifestName = null;
		for (int i = 0; i < existingManifests.size() + 1; i++) {
			String suffix = i == 0 ? Utils.EMPTY_STRING : String.valueOf(i);
			manifestName = META_INF_FOLDER + expectedManifestName + suffix + XML_EXTENSION;
			if (isValidName(manifestName, manifestNames)) {
				break;
			}
		}
		return manifestName;
	}
	
	/**
	 * Returns a list of document names
	 * @param documents list of {@link DSSDocument}s to get file names
	 * @return list of {@link String} document names
	 */
	public static List<String> getDSSDocumentNames(List<DSSDocument> documents) {
		return documents.stream().map(DSSDocument::getName).collect(Collectors.toList());
	}
	
	private static boolean isValidName(final String name, final List<String> notValidNames) {
		return !notValidNames.contains(name);
	}
	
	/**
	 * Checks if the current document an ASiC-E ZIP specific archive
	 * @param document {@link DSSDocument} to check
	 * @return TRUE if the document if a "package.zip" archive, FALSE otherwise
	 */
	public static boolean isASiCSArchive(DSSDocument document) {
		return Utils.areStringsEqual(PACKAGE_ZIP, document.getName());
	}

	/**
	 * Returns a content of the packageZip container
	 * @param packageZip {@link DSSDocument} ZIP container to get entries from
	 * @return list of {@link DSSDocument}s
	 */
	public static List<DSSDocument> getPackageZipContent(DSSDocument packageZip) {
		List<DSSDocument> result = new ArrayList<>();
		long containerSize = DSSUtils.getFileByteSize(packageZip);
		try (InputStream is = packageZip.openStream(); ZipInputStream packageZipInputStream = new ZipInputStream(is)) {
			ZipEntry entry;
			while ((entry = ASiCUtils.getNextValidEntry(packageZipInputStream)) != null) {
				result.add(ASiCUtils.getCurrentDocument(entry.getName(), packageZipInputStream, containerSize));
			}
		} catch (IOException e) {
			throw new DSSException("Unable to extract package.zip", e);
		}
		return result;
	}

}
