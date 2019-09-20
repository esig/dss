package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.parsing.CommonParsingResult;

/**
 * Contains results of TL/LOTL/pivot parsings
 *
 */
public class ParsingCache extends AbstractCache<CommonParsingResult> {

	@Override
	protected CacheType getCacheType() {
		return CacheType.PARSING;
	}

}
