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
package eu.europa.esig.dss.asic;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class is used to read an ASiC Container and to retrieve its content files
 */
public abstract class AbstractASiCContainerExtractor {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractASiCContainerExtractor.class);

	private final DSSDocument asicContainer;

	protected AbstractASiCContainerExtractor(DSSDocument asicContainer) {
		this.asicContainer = asicContainer;
	}

	public ASiCExtractResult extract() {
		ASiCExtractResult result = new ASiCExtractResult();
		
		long containerSize = DSSUtils.getFileByteSize(asicContainer);

		try (InputStream is = asicContainer.openStream(); ZipInputStream asicInputStream = new ZipInputStream(is)) {	
			int fileAmountCounter = 0;		
			ZipEntry entry;
			while ((entry = ASiCUtils.getNextValidEntry(asicInputStream)) != null) {
				ASiCUtils.validateAllowedFilesAmount(++fileAmountCounter);
				String entryName = entry.getName();
				if (isMetaInfFolder(entryName)) {
					if (isAllowedSignature(entryName)) {
						result.getSignatureDocuments().add(ASiCUtils.getCurrentDocument(entryName, asicInputStream, containerSize));
					} else if (isAllowedManifest(entryName)) {
						result.getManifestDocuments().add(ASiCUtils.getCurrentDocument(entryName, asicInputStream, containerSize));
					} else if (isAllowedArchiveManifest(entryName)) {
						result.getArchiveManifestDocuments().add(ASiCUtils.getCurrentDocument(entryName, asicInputStream, containerSize));
					} else if (isAllowedTimestamp(entryName)) {
						result.getTimestampDocuments().add(ASiCUtils.getCurrentDocument(entryName, asicInputStream, containerSize));
					} else if (!isFolder(entryName)) {
						result.getUnsupportedDocuments().add(ASiCUtils.getCurrentDocument(entryName, asicInputStream, containerSize));
					}
				} else if (!isFolder(entryName)) {
					if (isMimetype(entryName)) {
						result.setMimeTypeDocument(ASiCUtils.getCurrentDocument(entryName, asicInputStream, containerSize));
					} else {
						result.getSignedDocuments().add(ASiCUtils.getCurrentDocument(entryName, asicInputStream, containerSize));
					}
				}
			}

			if (Utils.isCollectionNotEmpty(result.getUnsupportedDocuments())) {
				LOG.warn("Unsupported files : {}", result.getUnsupportedDocuments());
			}

		} catch (IOException e) {
			LOG.warn("Unable to parse the container {}", e.getMessage());
		}

		result.setZipComment(getZipComment());

		return result;
	}

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

	private boolean isMimetype(String entryName) {
		return ASiCUtils.MIME_TYPE.equals(entryName);
	}

	private boolean isMetaInfFolder(String entryName) {
		return entryName.startsWith(ASiCUtils.META_INF_FOLDER);
	}

	private boolean isFolder(String entryName) {
		return entryName.endsWith("/");
	}

	abstract boolean isAllowedManifest(String entryName);

	abstract boolean isAllowedArchiveManifest(String entryName);

	abstract boolean isAllowedTimestamp(String entryName);

	abstract boolean isAllowedSignature(String entryName);

}
