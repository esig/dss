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

/**
 * This class contains constants for Manifest and its namespace.
 * 
 * @see <a href="http://docs.oasis-open.org/office/v1.2/OpenDocument-v1.2-part3.pdf">Open Document Format for Office
 *      Applications (OpenDocument) Version 1.2;
 *      Part 3: Packages</a>
 */
public final class ManifestNamespace {

	public static final String NS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
	public static final String MANIFEST = "manifest:manifest";
	public static final String VERSION = "manifest:version";
	public static final String FILE_ENTRY = "manifest:file-entry";
	public static final String FULL_PATH = "manifest:full-path";
	public static final String MEDIA_TYPE = "manifest:media-type";

	private ManifestNamespace() {
	}
}
