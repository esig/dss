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
import java.util.Objects;

/**
 * Computes summary for a single Trusted List processing result
 *
 */
public class TLInfo implements IdentifierBasedObject, Serializable {
	
	private static final long serialVersionUID = -1505115221927652721L;

	/** Address of the source */
	private final String url;

	/** The parent LOTL/TL referencing the current Trusted List */
	private final TLInfo parent;
	
	/** The download result record */
	private final DownloadInfoRecord downloadCacheInfo;

	/** The parsing result record */
	private final ParsingInfoRecord parsingCacheInfo;

	/** The validation result record */
	private final ValidationInfoRecord validationCacheInfo;

	/** OtherTSLPointer element extracted from the pointing TL/LOTL */
	private final OtherTSLPointer otherTSLPointer;

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
		this(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url, null);
	}

	/**
	 * The default constructor with parent TLInfo
	 *
	 * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
	 * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
	 * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
	 * @param url {@link String} address used to extract the entry
	 * @param parent {@link TLInfo} referencing the current Trusted List
	 */
	public TLInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo,
				  final ValidationInfoRecord validationCacheInfo, final String url, final TLInfo parent) {
		this(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url, parent, null);
	}
	
	/**
	 * The constructor with parent LOTLInfo and Mutual Recognition Agreement
	 *
	 * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
	 * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
	 * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
	 * @param url {@link String} address used to extract the entry
	 * @param parent {@link TLInfo} referencing the current Trusted List
	 * @param otherTSLPointer {@link OtherTSLPointer} element from the pointing TL/LOTL
	 */
	public TLInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo,
				  final ValidationInfoRecord validationCacheInfo, final String url, final TLInfo parent,
				  final OtherTSLPointer otherTSLPointer) {
		Objects.requireNonNull(url, "URL String shall be provided!");

		this.downloadCacheInfo = downloadCacheInfo;
		this.parsingCacheInfo = parsingCacheInfo;
		this.validationCacheInfo = validationCacheInfo;
		this.url = url;
		this.parent = parent;
		this.otherTSLPointer = otherTSLPointer;
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
	 * Returns the {@code TLInfo} referencing the current Trusted List
	 *
	 * @return {@link TLInfo}
	 */
	public TLInfo getParent() {
		return parent;
	}

	/**
	 * Gets the OtherTSLPointer element to referencing the current TL from the pointing TL/LOTL
	 *
	 * @return {@link OtherTSLPointer}
	 */
	public OtherTSLPointer getOtherTSLPointer() {
		return otherTSLPointer;
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
