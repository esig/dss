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
package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.tsl.identifier.LOTLIdentifier;

import java.util.List;

/**
 * Computes summary for a List of Trusted Lists processing result
 *
 */
public class LOTLInfo extends TLInfo {
	
	private static final long serialVersionUID = -8969562861281744320L;

	/**
	 * List of summary for TLs found inside the current LOTL
	 */
	private List<TLInfo> tlInfos;

	/**
	 * List of summary for pivots found inside the current LOTL
	 */
	private List<PivotInfo> pivotInfos;

	/**
	 * The default constructor
	 * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
	 * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
	 * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
	 * @param url {@link String} address used to extract the entry
	 */
	public LOTLInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo, 
			final ValidationInfoRecord validationCacheInfo, final String url) {
		super(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url);
	}
	
	/**
	 * Returns a list of {@code TLInfo}s summary for TL found in the LOTL
	 * @return list of {@link TLInfo}s
	 */
	public List<TLInfo> getTLInfos() {
		return tlInfos;
	}
	
	/**
	 * Sets a list of {@code TLInfo}s summary for TL found in the LOTL
	 * @param tlInfos list of {@link TLInfo}s
	 */
	public void setTlInfos(List<TLInfo> tlInfos) {
		this.tlInfos = tlInfos;
	}

	/**
	 * Returns a list of {@code PivotInfo}s summary for pivots found in the LOTL
	 * @return list of {@link PivotInfo}s
	 */
	public List<PivotInfo> getPivotInfos() {
		return pivotInfos;
	}

	/**
	 * Sets a list of {@code PivotInfo}s summary for pivots found in the LOTL
	 * @param pivotInfos list of {@link PivotInfo}s
	 */
	public void setPivotInfos(List<PivotInfo> pivotInfos) {
		this.pivotInfos = pivotInfos;
	}
	
	/**
	 * Checks if the current entry is a pivot info
	 * @return TRUE if it is a pivot, FALSE when it is a LOTL
	 */
	public boolean isPivot() {
		return false;
	}
	
	@Override
	protected Identifier buildIdentifier() {
		return new LOTLIdentifier(this);
	}

}
