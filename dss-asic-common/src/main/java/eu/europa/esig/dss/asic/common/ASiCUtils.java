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
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.zip.ZipEntry;

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

	/** The ASiC Archive Manifest name */
	public static final String ASIC_EVIDENCE_RECORD_MANIFEST_FILENAME = "ASiCEvidenceRecordManifest";

	/** The ASiC-E with XAdES Manifest name */
	public static final String ASIC_XAdES_MANIFEST_FILENAME = "manifest";

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

	/** The signature filename */
	public static final String SIGNATURES_FILENAME = "signatures";

	/** The timestamp filename */
	public static final String TIMESTAMP_FILENAME = "timestamp";

	/** The evidence record filename */
	public static final String EVIDENCE_RECORD_FILENAME = "evidencerecord";

	/** The signature file extension */
	public static final String CADES_SIGNATURE_EXTENSION = ".p7s";

	/** The timestamp file extension */
	public static final String TST_EXTENSION = ".tst";

	/** The evidence record IETF RFC 4998 file extension */
	public static final String ER_ASN1_EXTENSION = ".ers";

	/** The XML file extension */
	public static final String XML_EXTENSION = ".xml";

	/** The ASiC-S with XAdES signature document name (META-INF/signatures.xml) */
	public static final String SIGNATURES_XML = META_INF_FOLDER + SIGNATURES_FILENAME + XML_EXTENSION;

	/** The ASiC-E with XAdES for OpenDocument signature file name (META-INF/documentsignatures.xml) */
	public static final String OPEN_DOCUMENT_SIGNATURES = META_INF_FOLDER + "documentsignatures.xml";

	/** The default XML manifest filename (META-INF/manifest.xml) */
	public static final String ASICE_METAINF_MANIFEST = META_INF_FOLDER + ASIC_XAdES_MANIFEST_FILENAME + XML_EXTENSION;

	/** The default signature filename for ASiC-E with XAdES container */
	public static final String ASICE_METAINF_XADES_SIGNATURE = ASiCUtils.META_INF_FOLDER + "signatures001.xml";

	/** The default signature filename for ASiC-E with CAdES container */
	public static final String ASICE_METAINF_CADES_SIGNATURE = ASiCUtils.META_INF_FOLDER + "signature001.p7s";

	/** The default timestamp filename for ASiC-E with CAdES container */
	public static final String ASICE_METAINF_CADES_TIMESTAMP = ASiCUtils.META_INF_FOLDER + "timestamp001.tst";

	/** The default ASIC manifest filename for ASiC-E with CAdES container */
	public static final String ASICE_METAINF_CADES_MANIFEST = ASiCUtils.META_INF_FOLDER + "ASiCManifest001.xml";

	/** The default ASIC archive manifest filename for ASiC-E with CAdES container */
	public static final String ASICE_METAINF_CADES_ARCHIVE_MANIFEST = ASiCUtils.META_INF_FOLDER + "ASiCArchiveManifest001.xml";

	/** The ASiC-S with CAdES signature document name (META-INF/signature.p7s) */
	public static final String SIGNATURE_P7S = META_INF_FOLDER + SIGNATURE_FILENAME + CADES_SIGNATURE_EXTENSION;

	/** The ASiC-S with CAdES timestamp document name (META-INF/timestamp.tst) */
	public static final String TIMESTAMP_TST = META_INF_FOLDER + TIMESTAMP_FILENAME + TST_EXTENSION;

	/** The ASiC with XAdES evidence record ASN.1 document name (META-INF/evidencerecord.ers) */
	public static final String EVIDENCE_RECORD_ERS = META_INF_FOLDER + EVIDENCE_RECORD_FILENAME + ER_ASN1_EXTENSION;

	/** The ASiC with XAdES evidence record ASN.1 document name (META-INF/evidencerecord.xml) */
	public static final String EVIDENCE_RECORD_XML = META_INF_FOLDER + EVIDENCE_RECORD_FILENAME + XML_EXTENSION;

	/** Identifies a first bytes of a zip archive document */
	public static final byte[] ZIP_PREFIX = new byte[] {'P','K'};

	/**
	 * Singleton
	 */
	private ASiCUtils() {
		// empty
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
	 * Verifies if the {@code entryName} represents a timestamp file name
	 *
	 * @param entryName {@link String} name to check
	 * @return TRUE if the entryName represents a timestamp file name, FALSE otherwise
	 */
	public static boolean isEvidenceRecord(final String entryName) {
		return entryName.startsWith(META_INF_FOLDER) && entryName.contains(EVIDENCE_RECORD_FILENAME) &&
				(entryName.endsWith(XML_EXTENSION) || entryName.endsWith(ER_ASN1_EXTENSION));
	}

	/**
	 * Returns the target MimeType string
	 * 
	 * @param asicParameters {@link ASiCParameters}
	 * @return {@link String} MimeType
	 */
	public static String getMimeTypeString(final ASiCParameters asicParameters) {
		final MimeType mimeType = getMimeType(asicParameters);
		return mimeType.getMimeTypeString();
	}

	/**
	 * Returns a ZIP Comment String according to the given parameters
	 * 
	 * @param asicParameters {@link ASiCParameters}
	 * @return {@link String} zip comment
	 */
	public static String getZipComment(final ASiCParameters asicParameters) {
		if (asicParameters.isZipComment()) {
			return getZipComment(getMimeTypeString(asicParameters));
		}
		return Utils.EMPTY_STRING;
	}

	/**
	 * Returns a ZIP Comment String from the provided {@code MimeType}
	 *
	 * @param mimeType {@link MimeType}
	 * @return {@link String} zip comment
	 */
	public static String getZipComment(final MimeType mimeType) {
		return getZipComment(mimeType.getMimeTypeString());
	}

	/**
	 * Returns a ZIP Comment String from the provided {@code mimeTypeString}
	 * 
	 * @param mimeTypeString {@link String}
	 * @return {@link String} zip comment
	 */
	public static String getZipComment(final String mimeTypeString) {
		return MIME_TYPE_COMMENT + mimeTypeString;
	}

	/**
	 * Checks if the given MimeType is ASiC MimeType
	 * 
	 * @param mimeType {@link MimeType} to check
	 * @return TRUE if the given MimeType is ASiC MimeType, FALSE otherwise
	 */
	public static boolean isASiCMimeType(final MimeType mimeType) {
		return MimeTypeEnum.ASICS.equals(mimeType) || MimeTypeEnum.ASICE.equals(mimeType);
	}

	/**
	 * Checks if the given MimeType is OpenDocument MimeType
	 * 
	 * @param mimeType {@link MimeType} to check
	 * @return TRUE if the given MimeType is OpenDocument MimeType, FALSE otherwise
	 */
	public static boolean isOpenDocumentMimeType(final MimeType mimeType) {
		return MimeTypeEnum.ODT.equals(mimeType) || MimeTypeEnum.ODS.equals(mimeType) || MimeTypeEnum.ODG.equals(mimeType) || MimeTypeEnum.ODP.equals(mimeType);
	}

	/**
	 * Returns related {@code ASiCContainerType} for the given {@code asicMimeType}
	 * 
	 * @param asicMimeType {@link MimeType} to get {@link ASiCContainerType} for
	 * @return {@link ASiCContainerType}
	 */
	public static ASiCContainerType getASiCContainerType(final MimeType asicMimeType) {
		Objects.requireNonNull(asicMimeType, "MimeType cannot be null!");
		if (MimeTypeEnum.ASICS.equals(asicMimeType)) {
			return ASiCContainerType.ASiC_S;
		} else if (MimeTypeEnum.ASICE.equals(asicMimeType) || isOpenDocumentMimeType(asicMimeType)) {
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
		if (Utils.isStringNotBlank(asicParameters.getMimeType())) {
			return MimeType.fromMimeTypeString(asicParameters.getMimeType());
		}
		return isASiCE(asicParameters) ? MimeTypeEnum.ASICE : MimeTypeEnum.ASICS;
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
	public static boolean filesContainCorrectSignatureFileWithExtension(List<String> filenames, String extension) {
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
	public static boolean filesContainSignatures(List<String> filenames) {
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
		return filesContainCorrectSignatureFileWithExtension(filenames, CADES_SIGNATURE_EXTENSION)
				|| filesContainCorrectSignatureFileWithExtension(filenames, XML_EXTENSION)
				|| filesContainTimestamps(filenames);
	}

	/**
	 * Checks if the list of filenames contains a timestamp
	 * 
	 * @param filenames a list of filenames to check
	 * @return TRUE if the list of filenames contains the expected timestamp file,
	 *         FALSE otherwise
	 */
	public static boolean filesContainTimestamps(List<String> filenames) {
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
		try (InputStream is = document.openStream()) {
			return isZip(is);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to determine whether the document with name '%s' " +
					"represents a ZIP container. Reason : %s", document.getName(), e.getMessage()), e);
		}
	}

	/**
	 * Checks if the given {@code InputStream} contains a ZIP container
	 *
	 * @param is {@link InputStream} to check
	 * @return TRUE if the {@code InputStream} is a ZIP container, FALSE otherwise
	 */
	public static boolean isZip(InputStream is) {
		Objects.requireNonNull(is, "InputStream cannot be null!");
		try {
			return Utils.startsWith(is, ZIP_PREFIX);
		} catch (IOException e) {
			throw new IllegalInputException("Unable to read the 2 first bytes", e);
		}
	}

	/**
	 * Checks if the extracted filenames represent an ASiC with XAdES content
	 *
	 * @param filenames a list of {@link String} file names to check
	 * @return TRUE if the filenames represent an ASiC with XAdES content, FALSE
	 *         otherwise
	 */
	public static boolean isASiCWithXAdES(List<String> filenames) {
		return filesContainCorrectSignatureFileWithExtension(filenames, XML_EXTENSION);
	}
	
	/**
	 * Checks if the extracted filenames represent an ASiC with CAdES content
	 * 
	 * @param filenames a list of {@link String} file names to check
	 * @return TRUE if the filenames represent an ASiC with CAdES content, FALSE
	 *         otherwise
	 */
	public static boolean isASiCWithCAdES(List<String> filenames) {
		return filesContainCorrectSignatureFileWithExtension(filenames, CADES_SIGNATURE_EXTENSION)
				|| filesContainTimestamps(filenames);
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
	 * Checks if the archive represents an OpenDocument
	 *
	 * @param archiveContainer {@link DSSDocument} an archive to verify
	 * @return TRUE if the archive contains an OpenDocument mimetype, FALSE otherwise
	 */
	public static boolean isContainerOpenDocument(final DSSDocument archiveContainer) {
		DSSDocument mimetype = getMimetypeDocument(archiveContainer);
		return mimetype != null && isOpenDocument(mimetype);
	}

	private static DSSDocument getMimetypeDocument(DSSDocument archiveDocument) {
		List<DSSDocument> documents = ZipUtils.getInstance().extractContainerContent(archiveDocument);
		for (DSSDocument document : documents) {
			if (isMimetype(document.getName())) {
				return document;
			}
		}
		return null;
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
	 * Checks if the list of filenames contains a mimetype file
	 *
	 * @param filenames a list of filenames to check
	 * @return TRUE if the list of filenames contains a mimetype file,
	 *         FALSE otherwise
	 */
	public static boolean areFilesContainMimetype(List<String> filenames) {
		for (String filename : filenames) {
			if (isMimetype(filename)) {
				return true;
			}
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
		return MIME_TYPE.equals(entryName);
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
			throw new IllegalInputException(String.format("Unable to read mimetype file. Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * This method verifies whether the given container is of ASiC-S format type
	 *
	 * @param container {@link DSSDocument} to verify
	 * @return TRUE if the container is of ASiC-S type, FALSE otherwise
	 */
	public static boolean isASiCSContainer(DSSDocument container) {
		return ASiCContainerType.ASiC_S.equals(getContainerType(container));
	}

	/**
	 * This method verifies whether the given container is of ASiC-E format type
	 *
	 * @param container {@link DSSDocument} to verify
	 * @return TRUE if the container is of ASiC-E type, FALSE otherwise
	 */
	public static boolean isASiCEContainer(DSSDocument container) {
		return ASiCContainerType.ASiC_E.equals(getContainerType(container));
	}

	/**
	 * This method verifies type of the provided container document
	 *
	 * @param archiveContainer {@link DSSDocument} to verify
	 * @return {@link ASiCContainerType}
	 */
	public static ASiCContainerType getContainerType(DSSDocument archiveContainer) {
		List<String> entryNames = ZipUtils.getInstance().extractEntryNames(archiveContainer);

		DSSDocument mimetypeDocument = null;
		if (areFilesContainMimetype(entryNames)) {
			mimetypeDocument = getMimetypeDocument(archiveContainer);
		}
		String zipComment = getZipComment(archiveContainer);
		int signedDocumentsNumber = getNumberOfSignedRootDocuments(entryNames);

		return getContainerType(archiveContainer.getMimeType(), mimetypeDocument, zipComment, signedDocumentsNumber);
	}

	/**
	 * This method verifies whether the given {@code ASiCContent} is of ASiC-S format type
	 *
	 * @param asicContent {@link ASiCContent} to verify
	 * @return TRUE if the ASiC Content is of ASiC-S type, FALSE otherwise
	 */
	public static boolean isASiCSContainer(ASiCContent asicContent) {
		return ASiCContainerType.ASiC_S.equals(getContainerType(asicContent));
	}

	/**
	 * This method verifies whether the given {@code ASiCContent} is of ASiC-E format type
	 *
	 * @param asicContent {@link ASiCContent} to verify
	 * @return TRUE if the ASiC Content is of ASiC-E type, FALSE otherwise
	 */
	public static boolean isASiCEContainer(ASiCContent asicContent) {
		return ASiCContainerType.ASiC_E.equals(getContainerType(asicContent));
	}

	/**
	 * Returns container type
	 * 
	 * @param asicContent {@link ASiCContent}
	 * @return {@link ASiCContainerType}
	 */
	public static ASiCContainerType getContainerType(ASiCContent asicContent) {
		if (asicContent.getContainerType() != null) {
			return asicContent.getContainerType();
		}
		return getContainerType(asicContent.getAsicContainer().getMimeType(), asicContent.getMimeTypeDocument(),
				asicContent.getZipComment(), Utils.collectionSize(asicContent.getRootLevelSignedDocuments()));
	}

	private static int getNumberOfSignedRootDocuments(List<String> containerEntryNames) {
		int signedDocumentCounter = 0;
		for (String documentName : containerEntryNames) {
			if (!documentName.contains("/") && !isMimetype(documentName)) {
				++signedDocumentCounter;
			}
		}
		return signedDocumentCounter;
	}

	private static ASiCContainerType getContainerType(MimeType containerMimeType, DSSDocument mimetypeDocument,
			String zipComment, int rootSignedDocumentsNumber) {
		ASiCContainerType containerType = getContainerTypeFromMimeType(containerMimeType);
		if (containerType == null) {
			containerType = getContainerTypeFromMimeTypeDocument(mimetypeDocument);
			if (containerType == null) {
				containerType = getContainerTypeFromZipComment(zipComment);
			}
		}
		if (containerType == null) {
			LOG.info("Unable to define the ASiC Container type with its properties. Assume type based on root-level documents...");
			if (rootSignedDocumentsNumber == 1) {
				containerType = ASiCContainerType.ASiC_S;
			} else if (rootSignedDocumentsNumber > 1) {
				containerType = ASiCContainerType.ASiC_E;
			} else {
				LOG.warn("The provided container does not contain signer documents on the root level!");
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
			MimeType mimeTypeFromEmbeddedFile = getMimeType(mimetype);
			return getContainerTypeFromMimeType(mimeTypeFromEmbeddedFile);
		}
		return null;
	}

	private static ASiCContainerType getContainerTypeFromMimeType(MimeType mimeType) {
		if (isASiCMimeType(mimeType)) {
			return getASiCContainerType(mimeType);
		}
		return null;
	}

	/**
	 * Checks if the fileName matches to a Manifest name standard
	 *
	 * @param fileName {@link String} to check
	 * @return TRUE if the given name matches Manifest filename, FALSE otherwise
	 */
	public static boolean isManifest(String fileName) {
		return fileName.startsWith(META_INF_FOLDER) && fileName.contains(ASIC_MANIFEST_FILENAME)
				&& fileName.endsWith(XML_EXTENSION);
	}

	/**
	 * Checks if the fileName matches to an Archive Manifest name standard
	 * 
	 * @param fileName {@link String} to check
	 * @return TRUE if the given name matches ASiC Archive Manifest filename, FALSE otherwise
	 */
	public static boolean isArchiveManifest(String fileName) {
		return fileName.startsWith(META_INF_FOLDER) && fileName.contains(ASIC_ARCHIVE_MANIFEST_FILENAME)
				&& fileName.endsWith(XML_EXTENSION);
	}

	/**
	 * Checks if the fileName matches to an Evidence Record Manifest name standard
	 *
	 * @param fileName {@link String} to check
	 * @return TRUE if the given name matches ASiC Archive Manifest filename, FALSE otherwise
	 */
	public static boolean isEvidenceRecordManifest(String fileName) {
		return fileName.startsWith(META_INF_FOLDER) && fileName.contains(ASIC_EVIDENCE_RECORD_MANIFEST_FILENAME)
				&& fileName.endsWith(XML_EXTENSION);
	}

	/**
	 * Checks if the manifestFile covers a signature
	 *
	 * @param manifestFile {@link ManifestFile}
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

	/**
	 * This method searches for a document in a {@code documentList} with
	 * a name of {@code newDocumentVersion} and  replaces the found entry with the updated version
	 * or adds the document to the given list if no such entry has been found
	 *
	 * @param documentList a list of {@link DSSDocument}s
	 * @param newDocument {@link DSSDocument} to add
	 */
	public static void addOrReplaceDocument(List<DSSDocument> documentList, DSSDocument newDocument) {
		for (int i = 0; i < documentList.size(); i++) {
			if (newDocument.getName().equals(documentList.get(i).getName())) {
				documentList.set(i, newDocument);
				return;
			}
		}
		documentList.add(newDocument);
	}

	/**
	 * This method is used to ensure the mimetype file and zip-comment are present within the given {@code ASiCContent}.
	 * If the entry is not defined, a new value if created from {@code ASiCParameters}.
	 *
	 * @param asicContent {@link ASiCContent} to ensure a valid structure in
	 * @param asicParameters {@link ASiCParameters} to use to create missing entries
	 * @return {@link ASiCContent}
	 */
	public static ASiCContent ensureMimeTypeAndZipComment(ASiCContent asicContent, ASiCParameters asicParameters) {
		if (asicContent.getMimeTypeDocument() == null) {
			MimeType mimeType = getMimeType(asicContent, asicParameters);
			DSSDocument mimetypeDocument = createMimetypeDocument(mimeType);
			asicContent.setMimeTypeDocument(mimetypeDocument);
		}
		if (Utils.isStringEmpty(asicContent.getZipComment())) {
			String zipComment = getZipComment(asicContent, asicParameters);
			asicContent.setZipComment(zipComment);
		}
		return asicContent;
	}

	private static MimeType getMimeType(ASiCContent asicContent, ASiCParameters asicParameters) {
		MimeType mimeType = null;
		DSSDocument mimeTypeDocument = asicContent.getMimeTypeDocument();
		if (mimeTypeDocument != null) {
			// re-use the same mime-type when extending a container
			mimeType = getMimeType(mimeTypeDocument);
		}
		if (mimeType == null) {
			Objects.requireNonNull(asicParameters, "ASiCParameters shall be present for the requested operation!");
			mimeType = getMimeType(asicParameters);
		}
		return mimeType;
	}

	private static String getZipComment(ASiCContent asicContent, ASiCParameters asicParameters) {
		String zipComment = asicContent.getZipComment();
		if (Utils.isStringNotEmpty(zipComment)) {
			return zipComment;
		} else if (asicParameters != null) {
			return getZipComment(asicParameters);
		}
		return Utils.EMPTY_STRING;
	}

	private static DSSDocument createMimetypeDocument(final MimeType mimeType) {
		final byte[] mimeTypeBytes = mimeType.getMimeTypeString().getBytes(StandardCharsets.UTF_8);
		DSSDocument mimetypeDocument = new InMemoryDocument(mimeTypeBytes, MIME_TYPE);
		DSSZipEntryDocument zipEntryDocument = new ContainerEntryDocument(mimetypeDocument);
		zipEntryDocument.getZipEntry().setCompressionMethod(ZipEntry.STORED); // ensure STORED compression method
		return zipEntryDocument;
	}

	/**
	 * This method retrieves signed document from a root level of the container (used for ASiC-E container)
	 *
	 * @param asicContent {@link ASiCContent} representing the container structure
	 * @return a list of {@link DSSDocument}s
	 */
	public static List<DSSDocument> getRootLevelSignedDocuments(ASiCContent asicContent) {
		List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
		if (Utils.isCollectionEmpty(signedDocuments)) {
			return Collections.emptyList();

		} else if (Utils.collectionSize(signedDocuments) == 1) {
			return signedDocuments;
		}

		return getRootLevelDocuments(signedDocuments);
	}

	/**
	 * This method returns root-level documents across the provided list of documents
	 *
	 * @param documents list of {@link DSSDocument} to get root-level documents from
	 * @return list of {@link DSSDocument}s
	 */
	public static List<DSSDocument> getRootLevelDocuments(List<DSSDocument> documents) {
		List<DSSDocument> rootDocuments = new ArrayList<>();
		for (DSSDocument document : documents) {
			String documentName = document.getName();
			if (documentName != null && !documentName.contains("/") && !MIME_TYPE.equals(documentName)) {
				rootDocuments.add(document);
			}
		}
		return rootDocuments;
	}

	/**
	 * Returns a zip comment {@code String} from the ASiC container
	 *
	 * @param archiveContainer {@link DSSDocument} representing an Archive container
	 * @return {@link String} zip comment
	 */
	public static String getZipComment(DSSDocument archiveContainer) {
		byte[] buffer = DSSUtils.toByteArray(archiveContainer);
		if (Utils.isArrayEmpty(buffer)) {
			LOG.warn("An empty container obtained! Unable to extract zip comment.");
			return null;
		}

		final int len = buffer.length;
		final byte[] magicDirEnd = { 0x50, 0x4b, 0x05, 0x06 };

		// Check the buffer from the end
		for (int ii = len - 22; ii >= 0; ii--) {
			boolean isMagicStart = true;
			for (int jj = 0; jj < magicDirEnd.length; jj++) {
				if (buffer[ii + jj] != magicDirEnd[jj]) {
					isMagicStart = false;
					break;
				}
			}
			if (isMagicStart) {
				// Magic Start found!
				int commentLen = buffer[ii + 20] + buffer[ii + 21] * 256;
				int realLen = len - ii - 22;
				if (commentLen != realLen) {
					LOG.warn("WARNING! ZIP comment size mismatch: directory says len is {}, but file ends after {} bytes!", commentLen, realLen);
				}
				if (realLen == 0) {
					return null;
				}
				return new String(buffer, ii + 22, realLen);
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("Zip comment is not found in the provided container with name '{}'", archiveContainer.getName());
		}
		return null;
	}

	/**
	 * Transforms a list of given documents to a list of "simple" (only basic information) manifest entries
	 *
	 * @param documents list of {@link DSSDocument}s
	 * @return list of {@link ManifestEntry}s
	 */
	public static List<ManifestEntry> toSimpleManifestEntries(List<DSSDocument> documents) {
		List<ManifestEntry> entries = new ArrayList<>();
		for (DSSDocument document : documents) {
			ManifestEntry entry = new ManifestEntry();
			entry.setFileName(document.getName());
			entry.setMimeType(document.getMimeType());
			entry.setFound(true);
			entries.add(entry);
		}
		return entries;
	}

}
