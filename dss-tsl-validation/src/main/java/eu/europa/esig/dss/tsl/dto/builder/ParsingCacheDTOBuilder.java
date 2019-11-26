package eu.europa.esig.dss.tsl.dto.builder;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.tsl.TrustServiceProvider;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingResult;
import eu.europa.esig.dss.tsl.parsing.TLParsingResult;

public class ParsingCacheDTOBuilder extends AbstractCacheDTOBuilder<AbstractParsingResult> {

	private static final Logger LOG = LoggerFactory.getLogger(ParsingCacheDTOBuilder.class);
	
	public ParsingCacheDTOBuilder(final CachedEntry<AbstractParsingResult> cachedEntry) {
		super(cachedEntry);
	}
	
	@Override
	public ParsingCacheDTO build() {
		ParsingCacheDTO parsingCacheDTO = new ParsingCacheDTO(super.build());
		if (isResultExist()) {
			parsingCacheDTO.setSequenceNumber(getSequenceNumber());
			parsingCacheDTO.setVersion(getVersion());
			parsingCacheDTO.setTerritory(getTerritory());
			parsingCacheDTO.setIssueDate(getIssueDate());
			parsingCacheDTO.setNextUpdateDate(getNextUpdateDate());
			parsingCacheDTO.setDistributionPoints(getDistributionPoints());
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
		LOG.debug("Cannot extract Pivot URLs for the entry. The parsed file is not a LOTL. Return empty list.");
		return null;
	}

}
