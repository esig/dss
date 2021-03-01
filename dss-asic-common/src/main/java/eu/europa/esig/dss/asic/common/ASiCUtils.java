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

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

/**
 * Contains utils for working with ASiC containers
 */
public final class ASiCUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCUtils.class);

	/** The manifest name */
	public static final String MANIFEST_FILENAME = "Manifest";

	/** The ASiC Manifest name */
	public static final String ASIC_MANIFEST_FILENAME = "ASiCManifest";

	/** The ASiC Archive Manifest name */
	public static final String ASIC_ARCHIVE_MANIFEST_FILENAME = "ASiCArchiveManifest";

	/** The mimetype filename */
	public static final String MIME_TYPE = "mimetype";

	/** The mimetype comment */
	public static final String MIME_TYPE_COMMENT = MIME_TYPE + "=";

	/** The META-INF folder */
	public static final String META_INF_FOLDER = "META-INF/";

	/** The "package.zip" filename */
	public static final String PACKAGE_ZIP = "package.zip";

	/** The signature filename */
	public static final String SIGNATURE_FILENAME = "signature";

	/** The timestamp filename */
	public static final String TIMESTAMP_FILENAME = "timestamp";

	/** The signature file extension */
	public static final String CADES_SIGNATURE_EXTENSION = ".p7s";

	/** The timestamp file extension */
	public static final String TST_EXTENSION = ".tst";

	/** The XML file extension */
	public static final String XML_EXTENSION = ".xml";

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

	/**
	 * Returns the target MimeType string
	 * 
	 * @param asicParameters {@link ASiCParameters}
	 * @return {@link String} MimeType
	 */
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

	/**
	 * Returns a ZIP Comment String according to the given parameters
	 * 
	 * @param asicParameters {@link ASiCParameters}
	 * @return {@link String} zip comment
	 */
	public static String getZipComment(final ASiCParameters asicParameters) {
		if (asicParameters.isZipComment()) {
			return getZipComment(ASiCUtils.getMimeTypeString(asicParameters));
		}
		return Utils.EMPTY_STRING;
	}

	/**
	 * Returns a ZIP Comment String from the provided {@code mimeTypeString}
	 * 
	 * @param mimeTypeString {@link String}
	 * @return {@link String} zip comment
	 */
	public static String getZipComment(final String mimeTypeString) {
		return ASiCUtils.MIME_TYPE_COMMENT + mimeTypeString;
	}

	/**
	 * Checks if the given MimeType is ASiC MimeType
	 * 
	 * @param mimeType {@link MimeType} to check
	 * @return TRUE if the given MimeType is ASiC MimeType, FALSE otherwise
	 */
	public static boolean isASiCMimeType(final MimeType mimeType) {
		return MimeType.ASICS.equals(mimeType) || MimeType.ASICE.equals(mimeType);
	}

	/**
	 * Checks if the given MimeType is OpenDocument MimeType
	 * 
	 * @param mimeType {@link MimeType} to check
	 * @return TRUE if the given MimeType is OpenDocument MimeType, FALSE otherwise
	 */
	public static boolean isOpenDocumentMimeType(final MimeType mimeType) {
		return MimeType.ODT.equals(mimeType) || MimeType.ODS.equals(mimeType) || MimeType.ODG.equals(mimeType) || MimeType.ODP.equals(mimeType);
	}

	/**
	 * Returns related {@code ASiCContainerType} for the given {@code asicMimeType}
	 * 
	 * @param asicMimeType {@link MimeType} to get {@link ASiCContainerType} for
	 * @return {@link ASiCContainerType}
	 */
	public static ASiCContainerType getASiCContainerType(final MimeType asicMimeType) {
		if (MimeType.ASICS.equals(asicMimeType)) {
			return ASiCContainerType.ASiC_S;
		} else if (MimeType.ASICE.equals(asicMimeType) || isOpenDocumentMimeType(asicMimeType)) {
			return ASiCContainerType.ASiC_E;
		} else {
			throw new IllegalArgumentException("Not allowed mimetype '" + asicMimeType.getMimeTypeString() + "'");
		}
	}

	/**
	 * Checks if the parameters are configured for ASiCE creation
	 * 
	 * @param asicParameters {@link ASiCParameters}
	 * @return TRUE if parameters are configured for ASiCE, FALSE otherwise
	 */
	public static boolean isASiCE(final ASiCParameters asicParameters) {
		Objects.requireNonNull(asicParameters.getContainerType(), "ASiCContainerType must be defined!");
		return ASiCContainerType.ASiC_E.equals(asicParameters.getContainerType());
	}

	/**
	 * Checks if the parameters are configured for ASiCS creation
	 * 
	 * @param asicParameters {@link ASiCParameters}
	 * @return TRUE if parameters are configured for ASiCS, FALSE otherwise
	 */
	public static boolean isASiCS(final ASiCParameters asicParameters) {
		Objects.requireNonNull(asicParameters.getContainerType(), "ASiCContainerType must be defined!");
		return ASiCContainerType.ASiC_S.equals(asicParameters.getContainerType());
	}

	/**
	 * Returns a relevant MimeType for the provided parameters
	 * 
	 * @param asicParameters {@link ASiCParameters}
	 * @return {@link MimeType}
	 */
	public static MimeType getMimeType(ASiCParameters asicParameters) {
		return isASiCE(asicParameters) ? MimeType.ASICE : MimeType.ASICS;
	}
	
	/**
	 * Checks if the list of filenames contains a signature with the expected
	 * {@code extension}
	 * 
	 * @param filenames a list of file names
	 * @param extension {@link String} signature file extension to find
	 * @return TRUE if the list of filename contains the expected signature file,
	 *         FALSE otherwise
	 */
	public static boolean areFilesContainCorrectSignatureFileWithExtension(List<String> filenames, String extension) {
		for (String filename : filenames) {
			if (isSignature(filename) && filename.endsWith(extension)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if the list of filenames contains a signature(s)
	 * 
	 * @param filenames a list of file names
	 * @return TRUE if the list of filename contains a signature file(s)
	 */
	public static boolean areFilesContainSignatures(List<String> filenames) {
		for (String filename : filenames) {
			if (isSignature(filename)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if the list of filenames represents an ASiC container content
	 * 
	 * @param filenames a list of {@link String} file names
	 * @return TRUE if the list of filenames represents an ASiC container content,
	 *         FALSE otherwise
	 */
	public static boolean isAsicFileContent(List<String> filenames) {
		return areFilesContainCorrectSignatureFileWithExtension(filenames, CADES_SIGNATURE_EXTENSION)
				|| areFilesContainCorrectSignatureFileWithExtension(filenames, XML_EXTENSION)
				|| areFilesContainTimestamp(filenames);
	}

	/**
	 * Checks if the list of filenames contains a timestamp
	 * 
	 * @param filenames a list of filenames to check
	 * @return TRUE if the list of filenames contains the expected timestamp file,
	 *         FALSE otherwise
	 */
	public static boolean areFilesContainTimestamp(List<String> filenames) {
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
	
	/**
	 * Checks if the extracted filenames represent an ASiC with CAdES content
	 * 
	 * @param filenames a list of {@link String} file names to check
	 * @return TRUE if the filenames represent an ASiC with CAdES content, FALSE
	 *         otherwise
	 */
	public static boolean isASiCWithCAdES(List<String> filenames) {
		return areFilesContainCorrectSignatureFileWithExtension(filenames, CADES_SIGNATURE_EXTENSION)
				|| areFilesContainTimestamp(filenames);
	}

	/**
	 * Checks if the entryName is a relevant XAdES signature
	 * 
	 * @param entryName {@link String} to check
	 * @return TRUE if the entryName is a relevant XAdES signature, FALSE otherwise
	 */
	public static boolean isXAdES(final String entryName) {
		return isSignature(entryName) && entryName.endsWith(XML_EXTENSION);
	}

	/**
	 * Checks if the entryName is a relevant CAdES signature
	 * 
	 * @param entryName {@link String} to check
	 * @return TRUE if the entryName is a relevant CAdES signature, FALSE otherwise
	 */
	public static boolean isCAdES(final String entryName) {
		return isSignature(entryName) && (entryName.endsWith(CADES_SIGNATURE_EXTENSION));
	}

	/**
	 * Checks if the mimeType document defines an OpenDocument
	 * 
	 * @param mimeTypeDoc {@link DSSDocument} mimetype file extracted from an ASiC
	 *                    container
	 * @return TRUE if the mimeTypeDoc file defines an OpenDocument, FALSE otherwise
	 */
	public static boolean isOpenDocument(final DSSDocument mimeTypeDoc) {
		MimeType mimeType = getMimeType(mimeTypeDoc);
		if (mimeTypeDoc != null) {
			return isOpenDocumentMimeType(mimeType);
		}
		return false;
	}

	/**
	 * Checks if the given name is a "mimetype"
	 * 
	 * @param entryName {@link String} document name
	 * @return TRUE if the name is a "mimetype", FALSE otherwise
	 */
	public static boolean isMimetype(String entryName) {
		return ASiCUtils.MIME_TYPE.equals(entryName);
	}

	/**
	 * Extracts and returns MimeType from the document
	 * 
	 * @param mimeTypeDocument {@link DSSDocument} to get a MimeType of
	 * @return {@link MimeType}
	 */
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

	/**
	 * Returns target container type
	 * 
	 * @param archive         {@link DSSDocument} archive
	 * @param mimetype        {@link DSSDocument} mimetype file
	 * @param zipComment      {@link String} zipComment
	 * @param signedDocuments a list of {@link DSSDocument}s
	 * @return {@link ASiCContainerType}
	 */
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
	 *
	 * @param num number to transform
	 * @return {@link String}
	 */
	public static String getPadNumber(int num) {
		String numStr = String.valueOf(num);
		String zeroPad = "000";
		return zeroPad.substring(numStr.length()) + numStr;
	}

	/**
	 * Checks if the fileName matches to a Manifest name standard
	 *
	 * @param fileName {@link String} to check
	 * @return TRUE if the given name matches Manifest filename, FALSE otherwise
	 */
	public static boolean isManifest(String fileName) {
		return fileName.startsWith(ASiCUtils.META_INF_FOLDER) && fileName.contains(ASiCUtils.ASIC_MANIFEST_FILENAME)
				&& fileName.endsWith(ASiCUtils.XML_EXTENSION);
	}

	/**
	 * Checks if the fileName matches to an Archive Manifest name standard
	 * 
	 * @param fileName {@link String} to check
	 * @return TRUE if the given name matches ASiC Archive Manifest filename, FALSE otherwise
	 */
	public static boolean isArchiveManifest(String fileName) {
		return fileName.startsWith(ASiCUtils.META_INF_FOLDER) && fileName.contains(ASIC_ARCHIVE_MANIFEST_FILENAME)
				&& fileName.endsWith(XML_EXTENSION);
	}
	
	/**
	 * Generates an unique name for a new ASiC Manifest file, avoiding any name collision
	 *
	 * @param expectedManifestName {@link String} defines the expected name of the file without extension (e.g. "ASiCManifest")
	 * @param existingManifests list of existing {@link DSSDocument} manifests of the type present in the container
	 * @return {@link String} new manifest name
	 */
	public static String getNextASiCManifestName(final String expectedManifestName, final List<DSSDocument> existingManifests) {
		List<String> manifestNames = DSSUtils.getDocumentNames(existingManifests);
		
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
	
	private static boolean isValidName(final String name, final List<String> notValidNames) {
		return !notValidNames.contains(name);
	}
	
	/**
	 * Checks if the current document an ASiC-E ZIP specific archive
	 *
	 * @param document {@link DSSDocument} to check
	 * @return TRUE if the document if a "package.zip" archive, FALSE otherwise
	 */
	public static boolean isASiCSArchive(DSSDocument document) {
		return Utils.areStringsEqual(PACKAGE_ZIP, document.getName());
	}

	/**
	 * Checks if the manifestFile covers a signature
	 *
	 * @return TRUE if manifest entries contain a signature, FALSE otherwise
	 */
	public static boolean coversSignature(ManifestFile manifestFile) {
		for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
			if (isSignature(manifestEntry.getFileName())) {
				return true;
			}
		}
		return false;
	}

}
