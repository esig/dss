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
package eu.europa.esig.dss.asic.xades.definition;

import eu.europa.esig.dss.definition.AbstractPaths;
import eu.europa.esig.dss.definition.DSSNamespace;

/**
 * Path expressions for a Manifest
 */
public class ManifestPaths extends AbstractPaths {

	private static final long serialVersionUID = 1661986382868079585L;

	/** {@code "//manifest/file-entry"} */
	public static final String FILE_ENTRY_PATH = fromCurrentPosition(ManifestElement.MANIFEST, ManifestElement.FILE_ENTRY);

	/**
	 * Default constructor
	 */
	public ManifestPaths() {
	}

	/**
	 * Returns {@code "manifest:full-path"} with the given {@code manifestNamespace}'s prefix
	 *
	 * @param manifestNamespace {@link DSSNamespace}
	 * @return {@link String}
	 */
	public static String getFullPathAttribute(DSSNamespace manifestNamespace) {
		return manifestNamespace.getPrefix() + ':' + ManifestAttribute.FULL_PATH.getAttributeName();
	}

	/**
	 * Returns {@code "manifest:media-type"} with the given {@code manifestNamespace}'s prefix
	 *
	 * @param manifestNamespace {@link DSSNamespace}
	 * @return {@link String}
	 */
	public static String getMediaTypeAttribute(DSSNamespace manifestNamespace) {
		return manifestNamespace.getPrefix() + ':' + ManifestAttribute.MEDIA_TYPE.getAttributeName();
	}

}
