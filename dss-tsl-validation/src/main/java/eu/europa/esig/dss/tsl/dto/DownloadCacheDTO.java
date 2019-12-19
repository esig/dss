package eu.europa.esig.dss.tsl.dto;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;

public class DownloadCacheDTO extends AbstractCacheDTO implements DownloadInfoRecord {

	private static final long serialVersionUID = 514589372769360786L;

	private Date lastSuccessDownloadTime;

	public DownloadCacheDTO() {
	}

	public DownloadCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}

	@Override
	public Date getLastSuccessDownloadTime() {
		return lastSuccessDownloadTime;
	}

	public void setLastSuccessDownloadTime(Date lastSuccessDownloadTime) {
		this.lastSuccessDownloadTime = lastSuccessDownloadTime;
	}

	@Override
	public Date getLastDownloadAttemptTime() {
		List<Date> dates = new ArrayList<Date>();
		dates.add(lastSuccessDownloadTime);
		dates.add(getExceptionLastOccurrenceTime());
		dates.add(getLastStateTransitionTime());
		return compareDates(dates);
	}

	private Date compareDates(List<Date> dates) {
		Optional<Date> maxDate = dates.stream().filter(Objects::nonNull).max(Date::compareTo);
		if (maxDate.isPresent()) {
			return maxDate.get();
		} else {
			throw new IllegalStateException("All dates are null");
		}
	}
}
