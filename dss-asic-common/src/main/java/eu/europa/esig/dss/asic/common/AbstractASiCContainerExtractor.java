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
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * This class is used to read an ASiC Container and to retrieve its content files
 */
public abstract class AbstractASiCContainerExtractor {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractASiCContainerExtractor.class);

	/** Represents an ASiC container */
	private final DSSDocument asicContainer;

	/**
	 * The default constructor
	 * 
	 * @param asicContainer {@link DSSDocument} representing an ASiC container to
	 *                      extract entries from
	 */
	protected AbstractASiCContainerExtractor(DSSDocument asicContainer) {
		this.asicContainer = asicContainer;
	}

	/**
	 * Extracts a content (documents) embedded into the {@code asicContainer}
	 *
	 * @return {@link ASiCExtractResult}
	 */
	public ASiCExtractResult extract() {
		ASiCExtractResult result = new ASiCExtractResult();
		
		try {
			result = zipParsing(asicContainer);
			result.setRootContainer(asicContainer);
			result.setContainerType(getContainerType(result));

			if (Utils.isCollectionNotEmpty(result.getUnsupportedDocuments())) {
				LOG.warn("Unsupported files : {}", result.getUnsupportedDocuments());
			}

		} catch (IOException e) {
			LOG.warn("Unable to parse the container {}", e.getMessage());
		}

		result.setZipComment(getZipComment());
		
		return result;
	}

	private ASiCExtractResult zipParsing(DSSDocument asicContainer) throws IOException {
		ASiCExtractResult result = new ASiCExtractResult();

		List<DSSDocument> documents = ZipUtils.getInstance().extractContainerContent(asicContainer);
		if (Utils.isCollectionEmpty(documents)) {
			throw new DSSException(String.format(
					"The provided file with name '%s' does not contain documents inside. "
							+ "Probably file has an unsupported format or has been corrupted. "
							+ "The signature validation is not possible",
					asicContainer.getName()));
		}

		for (DSSDocument currentDocument : documents) {
			String entryName = currentDocument.getName();
			
			if (isMetaInfFolder(entryName)) {
				if (isAllowedSignature(entryName)) {
					result.getSignatureDocuments().add(currentDocument);
				} else if (isAllowedManifest(entryName)) {
					result.getManifestDocuments().add(currentDocument);
				} else if (isAllowedArchiveManifest(entryName)) {
					result.getArchiveManifestDocuments().add(currentDocument);
				} else if (isAllowedTimestamp(entryName)) {
					result.getTimestampDocuments().add(currentDocument);
				} else if (!isFolder(entryName)) {
					result.getUnsupportedDocuments().add(currentDocument);
				}
			} else if (!isFolder(entryName)) { 
				if (ASiCUtils.isMimetype(entryName)) {
					result.setMimeTypeDocument(currentDocument);
				} else {
					result.getSignedDocuments().add(currentDocument);
					if (ASiCUtils.isASiCSArchive(currentDocument)) {
						result.setContainerDocuments(ZipUtils.getInstance().extractContainerContent(currentDocument));
					}
				}
			}
			if (!isFolder(entryName)) {
				result.getAllDocuments().add(currentDocument);
			}
		}
		
		return result;
	}

	/**
	 * Returns a zip comment {@code String} from the ASiC container
	 *
	 * @return {@link String} zip comment
	 */
	public String getZipComment() {
		try (InputStream is = asicContainer.openStream()) {
			byte[] buffer = Utils.toByteArray(is);
			final int len = buffer.length;
			final byte[] magicDirEnd = { 0x50, 0x4b, 0x05, 0x06 };

			// Check the buffer from the end
			for (int ii = len - magicDirEnd.length - 22; ii >= 0; ii--) {
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
					return new String(buffer, ii + 22, realLen);

				}
			}
		} catch (Exception e) {
			LOG.warn("Unable to extract the ZIP comment : {}", e.getMessage());
		}
		return null;
	}

	private boolean isMetaInfFolder(String entryName) {
		return entryName.startsWith(ASiCUtils.META_INF_FOLDER);
	}
	
	private boolean isFolder(String entryName) {
		return entryName.endsWith("/");
	}

	private ASiCContainerType getContainerType(ASiCExtractResult result) {
		return ASiCUtils.getContainerType(asicContainer, result.getMimeTypeDocument(), result.getZipComment(),
				result.getSignedDocuments());
	}

	/**
	 * Checks if the given {@code String} file name represents an allowed manifest name
	 * for the current ASiC container format
	 *
	 * @param entryName {@link String} document name to check
	 * @return TRUE if the name represents an allowed manifest document name, FALSE otherwise
	 */
	protected abstract boolean isAllowedManifest(String entryName);

	/**
	 * Checks if the given {@code String} file name represents an allowed archive manifest name
	 * for the current ASiC container format
	 *
	 * @param entryName {@link String} document name to check
	 * @return TRUE if the name represents an allowed archive manifest document name, FALSE otherwise
	 */
	protected abstract boolean isAllowedArchiveManifest(String entryName);

	/**
	 * Checks if the given {@code String} file name represents an allowed timestamp document name
	 * for the current ASiC container format
	 *
	 * @param entryName {@link String} document name to check
	 * @return TRUE if the name represents an allowed timestamp document name, FALSE otherwise
	 */
	protected abstract boolean isAllowedTimestamp(String entryName);

	/**
	 * Checks if the given {@code String} file name represents an allowed signature document name
	 * for the current ASiC container format
	 *
	 * @param entryName {@link String} document name to check
	 * @return TRUE if the name represents an allowed signature document name, FALSE otherwise
	 */
	protected abstract boolean isAllowedSignature(String entryName);

}
