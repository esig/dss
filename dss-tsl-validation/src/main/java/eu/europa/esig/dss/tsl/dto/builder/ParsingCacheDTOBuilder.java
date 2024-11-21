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
package eu.europa.esig.dss.tsl.dto.builder;

import eu.europa.esig.dss.enumerations.TSLType;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.tsl.TrustServiceProvider;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingResult;
import eu.europa.esig.dss.tsl.parsing.TLParsingResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Builds {@code ParsingCacheDTO}
 */
public class ParsingCacheDTOBuilder extends AbstractCacheDTOBuilder<AbstractParsingResult> {

	private static final Logger LOG = LoggerFactory.getLogger(ParsingCacheDTOBuilder.class);

	/**
	 * Default constructor
	 *
	 * @param cachedEntry parsing cache entry
	 */
	public ParsingCacheDTOBuilder(final CachedEntry<AbstractParsingResult> cachedEntry) {
		super(cachedEntry);
	}
	
	@Override
	public ParsingCacheDTO build() {
		ParsingCacheDTO parsingCacheDTO = new ParsingCacheDTO(super.build());
		if (isResultExist()) {
			parsingCacheDTO.setTSLType(getTSLType());
			parsingCacheDTO.setSequenceNumber(getSequenceNumber());
			parsingCacheDTO.setVersion(getVersion());
			parsingCacheDTO.setTerritory(getTerritory());
			parsingCacheDTO.setIssueDate(getIssueDate());
			parsingCacheDTO.setNextUpdateDate(getNextUpdateDate());
			parsingCacheDTO.setDistributionPoints(getDistributionPoints());
			parsingCacheDTO.setStructureValidation(getStructureValidation());
			if (isLOTL()) {
				parsingCacheDTO.setLotlOtherPointers(getLOTLOtherPointers());
				parsingCacheDTO.setTlOtherPointers(getTLOtherPointers());
				parsingCacheDTO.setPivotUrls(getPivotUrls());
				parsingCacheDTO.setSigningCertificateAnnouncementUrl(getSigningCertificateAnnouncementUrl());
			} else {
				parsingCacheDTO.setTrustServiceProviders(getTrustServiceProviders());
			}
		}
		return parsingCacheDTO;
	}
	
	private boolean isLOTL() {
		return getResult() instanceof LOTLParsingResult;
	}

	private TSLType getTSLType() {
		return getResult().getTSLType();
	}
	
	private Integer getSequenceNumber() {
		return getResult().getSequenceNumber();
	}
	
	private Integer getVersion() {
		return getResult().getVersion();
	}
	
	private String getTerritory() {
		return getResult().getTerritory();
	}
	
	private Date getIssueDate() {
		return getResult().getIssueDate();
	}
	
	private Date getNextUpdateDate() {
		return getResult().getNextUpdateDate();
	}
	
	private List<String> getDistributionPoints() {
		return getResult().getDistributionPoints();
	}

	private List<String> getStructureValidation() {
		return getResult().getStructureValidation();
	}
	
	private List<TrustServiceProvider> getTrustServiceProviders() {
		AbstractParsingResult result = getResult();
		if (result instanceof TLParsingResult) {
			return ((TLParsingResult) getResult()).getTrustServiceProviders();
		}
		LOG.debug("Cannot extract trustServiceProviders for the entry. The parsed file is not a TL. Return empty list.");
		return Collections.emptyList();
	}
	
	private List<OtherTSLPointer> getLOTLOtherPointers() {
		AbstractParsingResult result = getResult();
		if (result instanceof LOTLParsingResult) {
			return ((LOTLParsingResult) getResult()).getLotlPointers();
		}
		LOG.debug("Cannot extract LOTL other Pointers for the entry. The parsed file is not a LOTL. Return empty list.");
		return Collections.emptyList();
	}
	
	private List<OtherTSLPointer> getTLOtherPointers() {
		AbstractParsingResult result = getResult();
		if (result instanceof LOTLParsingResult) {
			return ((LOTLParsingResult) getResult()).getTlPointers();
		}
		LOG.debug("Cannot extract TL other Pointers for the entry. The parsed file is not a LOTL. Return empty list.");
		return Collections.emptyList();
	}
	
	private List<String> getPivotUrls() {
		AbstractParsingResult result = getResult();
		if (result instanceof LOTLParsingResult) {
			return ((LOTLParsingResult) getResult()).getPivotURLs();
		}
		LOG.debug("Cannot extract Pivot URLs for the entry. The parsed file is not a LOTL. Return empty list.");
		return Collections.emptyList();
	}
	
	private String getSigningCertificateAnnouncementUrl() {
		AbstractParsingResult result = getResult();
		if (result instanceof LOTLParsingResult) {
			return ((LOTLParsingResult) getResult()).getSigningCertificateAnnouncementURL();
		}
		LOG.debug("Cannot extract Signing Certificate Announcement URL for the entry. The parsed file is not a LOTL. Return null.");
		return null;
	}

}
