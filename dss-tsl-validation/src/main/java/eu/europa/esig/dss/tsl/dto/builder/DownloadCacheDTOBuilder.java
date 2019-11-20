package eu.europa.esig.dss.tsl.dto.builder;

import java.util.Date;

import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.dto.DownloadCacheDTO;

public class DownloadCacheDTOBuilder extends AbstractCacheDTOBuilder<XmlDownloadResult> {
	
	public DownloadCacheDTOBuilder(final CachedEntry<XmlDownloadResult> cachedEntry) {
		super(cachedEntry);
	}
	
	@Override
	public DownloadCacheDTO build() {
		DownloadCacheDTO downloadCacheDTO = new DownloadCacheDTO(super.build());
		if (isResultExist()) {
			downloadCacheDTO.setLastSuccessDownloadTime(getLastSuccessDownloadTimeDate());
		}
		return downloadCacheDTO;
	}
	
	private Date getLastSuccessDownloadTimeDate() {
		return getResult().getLastSuccessDownloadTime();
	}

}
