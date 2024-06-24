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
package eu.europa.esig.dss.asic.common.extract;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * This class is used to read an ASiC Container and to retrieve its content files
 */
public abstract class DefaultASiCContainerExtractor implements ASiCContainerExtractor {

	private static final Logger LOG = LoggerFactory.getLogger(DefaultASiCContainerExtractor.class);

	/** Represents an ASiC container */
	private final DSSDocument asicContainer;

	/**
	 * The default constructor
	 * 
	 * @param asicContainer {@link DSSDocument} representing an ASiC container to
	 *                      extract entries from
	 */
	protected DefaultASiCContainerExtractor(DSSDocument asicContainer) {
		this.asicContainer = asicContainer;
	}

	/**
	 * Loads an implementation of {@code ASiCContainerExtractor} corresponding to {@code asicContainer} type
	 *
	 * @param asicContainer {@link DSSDocument} representing an ASiC archive
	 * @return {@link ASiCContainerExtractor}
	 */
	public static ASiCContainerExtractor fromDocument(DSSDocument asicContainer) {
		Objects.requireNonNull(asicContainer, "ASiC container cannot be null!");

		ServiceLoader<ASiCContainerExtractorFactory> serviceLoaders = ServiceLoader.load(ASiCContainerExtractorFactory.class);
		for (ASiCContainerExtractorFactory factory : serviceLoaders) {
			if (factory.isSupported(asicContainer)) {
				return factory.create(asicContainer);
			}
		}
		throw new UnsupportedOperationException("Document format not recognized/handled");
	}

	@Override
	public ASiCContent extract() {
		ASiCContent result = zipParsing(asicContainer);
		result.setZipComment(ASiCUtils.getZipComment(asicContainer));
		result.setContainerType(ASiCUtils.getContainerType(result));
		result.setContainerDocuments(getContainerDocuments(result));
		return result;
	}

	private ASiCContent zipParsing(DSSDocument asicContainer) {
		ASiCContent result = new ASiCContent();
		result.setAsicContainer(asicContainer);

		List<DSSDocument> documents = ZipUtils.getInstance().extractContainerContent(asicContainer);
		if (Utils.isCollectionEmpty(documents)) {
			throw new IllegalInputException(String.format(
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
				} else if (isAllowedEvidenceRecordManifest(entryName)) {
					result.getEvidenceRecordManifestDocuments().add(currentDocument);
				} else if (isAllowedTimestamp(entryName)) {
					result.getTimestampDocuments().add(currentDocument);
				} else if (isAllowedEvidenceRecord(entryName)) {
					result.getEvidenceRecordDocuments().add(currentDocument);
				} else if (!isFolder(entryName)) {
					result.getUnsupportedDocuments().add(currentDocument);
				}

			} else if (!isFolder(entryName)) { 
				if (ASiCUtils.isMimetype(entryName)) {
					result.setMimeTypeDocument(currentDocument);
				} else {
					result.getSignedDocuments().add(currentDocument);
				}

			} else {
				result.getFolders().add(currentDocument);
			}
		}

		if (Utils.isCollectionNotEmpty(result.getUnsupportedDocuments())) {
			LOG.warn("Unsupported files : {}", result.getUnsupportedDocuments());
		}
		return result;
	}

	private List<DSSDocument> getContainerDocuments(ASiCContent asicContent) {
		List<DSSDocument> containerDocuments = new ArrayList<>();
		if (ASiCUtils.isASiCSContainer(asicContent)) {
			for (DSSDocument signerDocument : asicContent.getRootLevelSignedDocuments()) {
				if (Utils.isCollectionNotEmpty(containerDocuments)) {
					LOG.warn("More than one ZIP archive found on a root level of the ASiC-S container! " +
							"Extraction of embedded documents not possible.");
					return Collections.emptyList();
				}
				if (ASiCUtils.isZip(signerDocument)) {
					containerDocuments.addAll(ZipUtils.getInstance().extractContainerContent(signerDocument));
				}
			}
		}
		return containerDocuments;
	}

	private boolean isMetaInfFolder(String entryName) {
		return entryName.startsWith(ASiCUtils.META_INF_FOLDER);
	}
	
	private boolean isFolder(String entryName) {
		return entryName.endsWith("/");
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
	 * Checks if the given {@code String} file name represents an allowed evidence record manifest name
	 * for the current ASiC container format
	 *
	 * @param entryName {@link String} document name to check
	 * @return TRUE if the name represents an allowed evidence record manifest document name, FALSE otherwise
	 */
	protected abstract boolean isAllowedEvidenceRecordManifest(String entryName);

	/**
	 * Checks if the given {@code String} file name represents an allowed signature document name
	 * for the current ASiC container format
	 *
	 * @param entryName {@link String} document name to check
	 * @return TRUE if the name represents an allowed signature document name, FALSE otherwise
	 */
	protected abstract boolean isAllowedSignature(String entryName);

	/**
	 * Checks if the given {@code String} file name represents an allowed timestamp document name
	 * for the current ASiC container format
	 *
	 * @param entryName {@link String} document name to check
	 * @return TRUE if the name represents an allowed timestamp document name, FALSE otherwise
	 */
	protected abstract boolean isAllowedTimestamp(String entryName);

	/**
	 * Checks if the given {@code String} file name represents an allowed evidence record document name
	 * for the current ASiC container format
	 *
	 * @param entryName {@link String} document name to check
	 * @return TRUE if the name represents an allowed evidence record document name, FALSE otherwise
	 */
	protected abstract boolean isAllowedEvidenceRecord(String entryName);

}
