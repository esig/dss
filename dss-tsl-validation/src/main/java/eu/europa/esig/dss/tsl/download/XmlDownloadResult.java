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
package eu.europa.esig.dss.tsl.download;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.tsl.cache.CachedResult;
import eu.europa.esig.dss.tsl.sha2.DocumentWithSha2;

import java.util.Collections;
import java.util.List;

/**
 * Defines the download result
 */
public class XmlDownloadResult implements CachedResult {

	/** The downloaded document */
	private final DSSDocument dssDocument;

	/** Digest of a canonicalized document */
	private final Digest digest;

	/**
	 * Default constructor
	 *
	 * @param dssDocument {@link DSSDocument} downloaded document
	 * @param digest {@link Digest} of the canonicalized document
	 */
	public XmlDownloadResult(DSSDocument dssDocument, Digest digest) {
		this.dssDocument = dssDocument;
		this.digest = digest;
	}

	/**
	 * Gets the downloaded document
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getDSSDocument() {
		return dssDocument;
	}

	/**
	 * Gets digest of a canonicalized document
	 *
	 * @return {@link Digest}
	 */
	public Digest getDigest() {
		return digest;
	}

	/**
	 * Returns error messages occurred during sha2 processing, if applicable
	 *
	 * @return a list of {@link String}s if errors occurred during sha2 processing, empty list otherwise
	 */
	public List<String> getSha2ErrorMessages() {
		if (dssDocument instanceof DocumentWithSha2) {
			return ((DocumentWithSha2) dssDocument).getErrors();
		}
		return Collections.emptyList();
	}

}
