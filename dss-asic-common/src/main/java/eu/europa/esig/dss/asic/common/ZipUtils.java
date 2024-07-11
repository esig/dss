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

import eu.europa.esig.dss.model.DSSDocument;

import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * The class is used for processing (reading and creation) of ZIP archives
 * See {@code eu.europa.esig.dss.asic.common.ZipContainerHandler}
 *
 */
public final class ZipUtils {

	/** Singleton */
	private static ZipUtils singleton;

	/**
	 * Provides utils for ZIP-archive content extraction
	 */
	private ZipContainerHandlerBuilder<?> zipContainerHandlerBuilder = new SecureContainerHandlerBuilder();

	/**
	 * Singleton
	 */
	private ZipUtils() {
		// empty
	}

	/**
	 * Returns an instance of the ZipUtils class
	 * 
	 * @return {@link ZipUtils} singleton
	 */
	public static ZipUtils getInstance() {
		if (singleton == null) {
			singleton = new ZipUtils();
		}
		return singleton;
	}

	/**
	 * Sets a builder to create an instance of a handler to process ZIP-content retrieving.
	 * The handler will be created on each call of ZipUtils class.
	 * Default : {@code SecureContainerHandlerBuilder}
	 *
	 * @param zipContainerHandlerBuilder {@link ZipContainerHandlerBuilder}
	 */
	public void setZipContainerHandlerBuilder(ZipContainerHandlerBuilder<?> zipContainerHandlerBuilder) {
		Objects.requireNonNull(zipContainerHandlerBuilder, "ZipContainerHandlerBuilder shall be defined!");
		this.zipContainerHandlerBuilder = zipContainerHandlerBuilder;
	}

	/**
	 * Extracts a list of {@code DSSDocument} from the given ZIP-archive
	 * 
	 * @param zipPackage {@link DSSDocument}
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> extractContainerContent(DSSDocument zipPackage) {
		return getZipContainerHandler().extractContainerContent(zipPackage);
	}

	/**
	 * Returns a list of ZIP archive entry names
	 * 
	 * @param zipPackage {@link DSSDocument}
	 * @return a list of {@link String} entry names
	 */
	public List<String> extractEntryNames(DSSDocument zipPackage) {
		return getZipContainerHandler().extractEntryNames(zipPackage);
	}

	/**
	 * Creates a ZIP-Archive with the given {@code containerEntries}
	 * 
	 * @param containerEntries a list of {@link DSSDocument}s to embed into the new
	 *                         container instance
	 * @param creationTime     (Optional) {@link Date} defined time of an archive
	 *                         creation, will be set for all embedded files. If
	 *                         null, the local current time will be used
	 * @param zipComment       (Optional) {@link String} defined a zipComment
	 * @return {@link DSSDocument} ZIP-Archive
	 */
	public DSSDocument createZipArchive(List<DSSDocument> containerEntries, Date creationTime, String zipComment) {
		return getZipContainerHandler().createZipArchive(containerEntries, creationTime, zipComment);
	}

	/**
	 * Creates a ZIP-Archive with the given {@code asicContent}, indicating teh current creation time
	 *
	 * @param asicContent {@link ASiCContent} to create a new ZIP Archive from
	 * @return {@link DSSDocument} ZIP-Archive
	 */
	public DSSDocument createZipArchive(ASiCContent asicContent) {
		return createZipArchive(asicContent, new Date());
	}

	/**
	 * Creates a ZIP-Archive with the given {@code asicContent}
	 *
	 * @param asicContent      {@link ASiCContent} to create a new ZIP Archive from
	 * @param creationTime     (Optional) {@link Date} defined time of an archive
	 *                         creation, will be set for all embedded files. If
	 *                         null, the local current time will be used
	 * @return {@link DSSDocument} ZIP-Archive
	 */
	public DSSDocument createZipArchive(ASiCContent asicContent, Date creationTime) {
		return createZipArchive(asicContent.getAllDocuments(), creationTime, asicContent.getZipComment());
	}

	/**
	 * Returns a new instance of {@code ZipContainerHandler}
	 *
	 * @return {@link ZipContainerHandler}
	 */
	private ZipContainerHandler getZipContainerHandler() {
		return zipContainerHandlerBuilder.build();
	}

}
