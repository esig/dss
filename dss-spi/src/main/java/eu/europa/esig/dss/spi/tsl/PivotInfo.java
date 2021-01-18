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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.identifier.PivotIdentifier;

import java.util.HashMap;
import java.util.Map;

/**
 * Contains information about a pivot
 */
public class PivotInfo extends LOTLInfo {

	private static final long serialVersionUID = 1724138551018429654L;
	
	/** Map between certificates and their change statuses in the current Pivot */
	private Map<CertificateToken, CertificatePivotStatus> certificateStatusMap = new HashMap<>();
	
	/** Associated XML LOTL Location */
	private String lotlLocation;

	/**
	 * The default constructor
	 *
	 * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
	 * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
	 * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
	 * @param url {@link String} address used to extract the entry
	 * @param certificates map between {@link CertificateToken} and {@link CertificatePivotStatus}
	 * 					map between certificates and their statuses in the current pivot
	 * @param lotlLocation {@link String} the associated with the pivot LOTL location
	 */
	public PivotInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo, 
			final ValidationInfoRecord validationCacheInfo, final String url, final Map<CertificateToken, CertificatePivotStatus> certificates,
			final String lotlLocation) {
		super(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url);
		this.certificateStatusMap = certificates;
		this.lotlLocation = lotlLocation;
	}
	
	/**
	 * Returns a map of certificate tokens with a status regarding to the current pivot
	 *
	 * @return map between {@link CertificateToken} and {@link CertificatePivotStatus}
	 */
	public Map<CertificateToken, CertificatePivotStatus> getCertificateStatusMap() {
		return certificateStatusMap;
	}
	
	/**
	 * Returns the associated with the pivot LOTL Location url
	 *
	 * @return {@link String} LOTL location url
	 */
	public String getLOTLLocation() {
		return lotlLocation;
	}
	
	@Override
	public boolean isPivot() {
		return true;
	}
	
	@Override
	protected Identifier buildIdentifier() {
		return new PivotIdentifier(this);
	}

}
