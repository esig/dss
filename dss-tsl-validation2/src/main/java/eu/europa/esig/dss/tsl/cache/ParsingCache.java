package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;

/**
 * Contains results of TL/LOTL/pivot parsings
 *
 */
public class ParsingCache extends AbstractCache<AbstractParsingResult> {

	@Override
	protected CacheType getCacheType() {
		return CacheType.PARSING;
	}

}
