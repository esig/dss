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
package eu.europa.esig.dss.tsl.dto;

import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The download record DTO
 */
public class DownloadCacheDTO extends AbstractCacheDTO implements DownloadInfoRecord {

	private static final long serialVersionUID = 514589372769360786L;

	/** An error message occurred during sha2 processing */
	private String sha2ErrorMessage;

	/**
	 * Empty constructor
	 */
	public DownloadCacheDTO() {
		// empty
	}

	/**
	 * Copies the cache DTO
	 *
	 * @param cacheDTO {@link AbstractCacheDTO}
	 */
	public DownloadCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}

	@Override
	public Date getLastDownloadAttemptTime() {
		List<Date> dates = new ArrayList<>();
		dates.add(getLastSuccessSynchronizationTime());
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

	/**
	 * Gets an error message occurred during the sha2 processing
	 *
	 * @return {@link String}
	 */
	public String getSha2ErrorMessage() {
		return sha2ErrorMessage;
	}

	/**
	 * Sets an error message occurred during sha2 file processing
	 *
	 * @param sha2ErrorMessage {@link String}
	 */
	public void setSha2ErrorMessage(String sha2ErrorMessage) {
		this.sha2ErrorMessage = sha2ErrorMessage;
	}

}
