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
package eu.europa.esig.dss.validation.job.dto.builder;

import eu.europa.esig.dss.validation.job.cache.state.CachedEntry;
import eu.europa.esig.dss.validation.job.dto.AbstractCacheDTO;
import eu.europa.esig.dss.validation.job.dto.AbstractParsingCacheDTO;
import eu.europa.esig.dss.validation.job.parsing.ParsingResult;

import java.util.List;

/**
 * Builds {@code AbstractParsingCacheDTO}
 */
public abstract class AbstractParsingCacheDTOBuilder extends AbstractCacheDTOBuilder<ParsingResult> {

	/**
	 * Default constructor
	 *
	 * @param cachedEntry parsing cache entry
	 */
	protected AbstractParsingCacheDTOBuilder(final CachedEntry<ParsingResult> cachedEntry) {
		super(cachedEntry);
	}
	
	@Override
	public AbstractParsingCacheDTO build() {
		AbstractParsingCacheDTO parsingCacheDTO = init(super.build());
		if (isResultExist()) {
			build(parsingCacheDTO);
		}
		return parsingCacheDTO;
	}

	/**
	 * Instantiates a new {@code AbstractParsingCacheDTO} from {@link AbstractCacheDTO}
	 *
	 * @param abstractCacheDTO {@link AbstractCacheDTO}
	 * @return {@link AbstractParsingCacheDTO}
	 */
	protected abstract AbstractParsingCacheDTO init(AbstractCacheDTO abstractCacheDTO);

	/**
	 * Builds {@link AbstractParsingCacheDTO}
	 *
	 * @param parsingCacheDTO {@link AbstractParsingCacheDTO} to fill
	 */
	protected void build(AbstractParsingCacheDTO parsingCacheDTO) {
		parsingCacheDTO.setStructureValidationMessages(getStructureValidationMessages());
	}

	private List<String> getStructureValidationMessages() {
		return getResult().getStructureValidationMessages();
	}

}
