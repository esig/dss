/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.common;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * The interface provides utilities for data extraction/creation of ZIP-archives
 *
 */
public interface ZipContainerHandler {

	/**
	 * Extracts a list of {@code DSSDocument} from the given ZIP-archive
	 * 
	 * @param zipArchive {@link DSSDocument}
	 * @return a list of {@link DSSDocument}s
	 */
	List<DSSDocument> extractContainerContent(DSSDocument zipArchive);

	/**
	 * Returns a list of ZIP archive entry names
	 * 
	 * @param zipArchive {@link DSSDocument}
	 * @return a list of {@link String} entry names
	 */
	List<String> extractEntryNames(DSSDocument zipArchive);

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
	DSSDocument createZipArchive(List<DSSDocument> containerEntries, Date creationTime, String zipComment);

}
