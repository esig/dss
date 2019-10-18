package eu.europa.esig.dss.tsl.parsing;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.utils.Utils;

public class ParsingUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ParsingUtils.class);
	
	/**
	 * Extracts XML LOTL Pointer from a parsing cache of a pivot
	 * @param parsingCacheDTO {@link ParsingCacheDTO} to extrac value from
	 * @return {@link OtherTSLPointer} XML LOTL Pointer
	 */
	public static OtherTSLPointer getXMLLOTLPointer(final ParsingCacheDTO parsingCacheDTO) {
		int nbLOTLPointersInPivot = 0;
		if (parsingCacheDTO != null && parsingCacheDTO.isResultExist()) {
			List<OtherTSLPointer> lotlOtherPointers = parsingCacheDTO.getLotlOtherPointers();
			nbLOTLPointersInPivot = Utils.collectionSize(lotlOtherPointers);
			if (nbLOTLPointersInPivot == 1) {
				return lotlOtherPointers.get(0);
			}
		} else {
			LOG.warn("The provided parsing cache DTO is null or does not exist!");
		}
		LOG.warn("Unable to find the XML LOTL Pointer in the pivot (nb occurrences : {}). Must be one occurence!", nbLOTLPointersInPivot);
		return null;
	}

}
