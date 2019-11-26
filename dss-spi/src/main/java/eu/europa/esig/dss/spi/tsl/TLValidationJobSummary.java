package eu.europa.esig.dss.spi.tsl;

import java.util.List;

import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.utils.Utils;

/**
 * Computes summary for TLValidationJob
 *
 */
public class TLValidationJobSummary {
	
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
				if (identifier.equals(tlInfo.getIdentifier())) {
					return tlInfo;
				}
			}
		}

		if (Utils.isCollectionNotEmpty(lotlInfos)) {
			for (LOTLInfo lotlInfo : lotlInfos) {
				for (TLInfo tlInfo : lotlInfo.getTLInfos()) {
					if (identifier.equals(tlInfo.getIdentifier())) {
						return tlInfo;
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
				if (identifier.equals(lotlInfo.getIdentifier())) {
					return lotlInfo;
				}
			}
		}
		return null;
	}

}
