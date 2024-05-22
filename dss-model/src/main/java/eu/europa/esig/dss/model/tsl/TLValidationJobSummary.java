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
package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.utils.Utils;

import java.io.Serializable;
import java.util.List;

/**
 * Computes summary for TLValidationJob
 *
 */
public class TLValidationJobSummary implements Serializable {

	private static final long serialVersionUID = -1035891155378415013L;

	/**
	 * A list of LOTLs with a relationship between their TLs and pivots
	 */
	private final List<LOTLInfo> lotlInfos;
	
	/**
	 * List of TL infos for otherTLSources
	 */
	private final List<TLInfo> otherTLInfos;
	
	/**
	 * The default constructor
	 * 
	 * @param lotlInfos
	 *                     a list of LOTL info
	 * @param otherTLInfos
	 *                     a list of other trusted lists which are not linked to the
	 *                     LOTLs
	 */
	public TLValidationJobSummary(final List<LOTLInfo> lotlInfos, final List<TLInfo> otherTLInfos) {
		if (Utils.isCollectionEmpty(lotlInfos) && Utils.isCollectionEmpty(otherTLInfos)) {
			throw new IllegalArgumentException("LOTL or TL Info shall be provided!");
		}
		this.lotlInfos = lotlInfos;
		this.otherTLInfos = otherTLInfos;
	}

	/**
	 * Returns a list of LOTLInfos for all processed LOTLs
	 * @return list of {@link LOTLInfo}s
	 */
	public List<LOTLInfo> getLOTLInfos() {
		return lotlInfos;
	}
	
	/**
	 * Returns a list of TLInfos for other TLs
	 * @return list of {@link TLInfo}s
	 */
	public List<TLInfo> getOtherTLInfos() {
		return otherTLInfos;
	}
	
	/**
	 * Returns an amount of processed TLs during the TL Validation job
	 * @return {@code int} number of processed TLs
	 */
	public int getNumberOfProcessedTLs() {
		int amount = 0;
		if (Utils.isCollectionNotEmpty(otherTLInfos)) {
			amount += otherTLInfos.size();
		}
		if (Utils.isCollectionNotEmpty(lotlInfos)) {
			for (LOTLInfo lotlInfo : lotlInfos) {
				amount += lotlInfo.getTLInfos().size();
			}
		}
		return amount;
	}
	
	/**
	 * Returns an amount of processed LOTLs during the TL Validation job
	 * @return {@code int} number of processed LOTLs
	 */
	public int getNumberOfProcessedLOTLs() {
		if (Utils.isCollectionNotEmpty(lotlInfos)) {
			return lotlInfos.size();
		}
		return 0;
	}
	
	/**
	 * Returns a TLInfo object by Identifier
	 * 
	 * @param identifier
	 *            the Identifier of the searched TL
	 * @return a TLInfo or null
	 */
	public TLInfo getTLInfoById(Identifier identifier) {
		if (Utils.isCollectionNotEmpty(otherTLInfos)) {
			for (TLInfo tlInfo : otherTLInfos) {
				if (identifier.equals(tlInfo.getDSSId())) {
					return tlInfo;
				}
			}
		}

		if (Utils.isCollectionNotEmpty(lotlInfos)) {
			for (LOTLInfo lotlInfo : lotlInfos) {
				if (Utils.isCollectionNotEmpty(lotlInfo.getTLInfos())) {
					for (TLInfo tlInfo : lotlInfo.getTLInfos()) {
						if (identifier.equals(tlInfo.getDSSId())) {
							return tlInfo;
						}
					}
				}
			}
		}

		return null;
	}

	/**
	 * Returns a LOTLInfo object by Identifier
	 * 
	 * @param identifier
	 *            the Identifier of the searched LOTL
	 * @return a LOTLInfo or null
	 */
	public LOTLInfo getLOTLInfoById(Identifier identifier) {
		if (Utils.isCollectionNotEmpty(lotlInfos)) {
			for (LOTLInfo lotlInfo : lotlInfos) {
				if (identifier.equals(lotlInfo.getDSSId())) {
					return lotlInfo;
				}
			}
		}
		return null;
	}

}
