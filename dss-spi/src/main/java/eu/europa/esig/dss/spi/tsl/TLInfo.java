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
package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;
import eu.europa.esig.dss.spi.tsl.identifier.TrustedListIdentifier;

import java.io.Serializable;

/**
 * Computes summary for a single Trusted List processing result
 *
 */
public class TLInfo implements IdentifierBasedObject, Serializable {
	
	private static final long serialVersionUID = -1505115221927652721L;

	/**
	 * Address of the source
	 */
	private final String url;
	
	/** The download result record */
	private final DownloadInfoRecord downloadCacheInfo;

	/** The parsing result record */
	private final ParsingInfoRecord parsingCacheInfo;

	/** The validation result record */
	private final ValidationInfoRecord validationCacheInfo;

	/** Cached Identifier instance */
	private Identifier identifier;
	
	/**
	 * The default constructor
	 *
	 * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
	 * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
	 * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
	 * @param url {@link String} address used to extract the entry
	 */
	public TLInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo, 
			final ValidationInfoRecord validationCacheInfo, final String url) {
		this.downloadCacheInfo = downloadCacheInfo;
		this.parsingCacheInfo = parsingCacheInfo;
		this.validationCacheInfo = validationCacheInfo;
		this.url = url;
	}
	
	/**
	 * Returns Download Cache Info
	 *
	 * @return {@link DownloadInfoRecord}
	 */
	public DownloadInfoRecord getDownloadCacheInfo() {
		return downloadCacheInfo;
	}
	
	/**
	 * Returns Parsing Cache Info
	 *
	 * @return {@link ParsingInfoRecord}
	 */
	public ParsingInfoRecord getParsingCacheInfo() {
		return parsingCacheInfo;
	}
	
	/**
	 * Returns Validation Cache Info
	 *
	 * @return {@link ValidationInfoRecord}
	 */
	public ValidationInfoRecord getValidationCacheInfo() {
		return validationCacheInfo;
	}
	
	/**
	 * Returns a URL that was used to download the remote file
	 *
	 * @return {@link String} url
	 */
	public String getUrl() {
		return url;
	}
	
	/**
	 * Returns the TL id
	 *
	 * @return {@link String} id
	 */
	public Identifier getDSSId() {
		if (identifier == null) {
			identifier = buildIdentifier();
		}
		return identifier;
	}

	/**
	 * Builds the identifier
	 *
	 * @return {@link Identifier}
	 */
	protected Identifier buildIdentifier() {
		return new TrustedListIdentifier(this);
	}

	/**
	 * Returns the String representation of the identifier
	 *
	 * @return {@link String}
	 */
	public String getDSSIdAsString() {
		return getDSSId().asXmlId();
	}

}
