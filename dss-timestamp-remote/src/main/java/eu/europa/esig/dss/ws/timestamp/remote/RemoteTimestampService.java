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
package eu.europa.esig.dss.ws.timestamp.remote;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.exception.DSSRemoteServiceException;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * The remote service representing a timestamping service
 */
public class RemoteTimestampService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteTimestampService.class);

	/** The TSP Source to use to request timestamps */
	private TSPSource tspSource;

	/**
	 * Default construction instantiating object with null TSPSource
	 */
	public RemoteTimestampService() {
		// empty
	}

	/**
	 * Sets the TSP Source
	 *
	 * @param tspSource {@link TSPSource}
	 */
	public void setTSPSource(TSPSource tspSource) {
		this.tspSource = tspSource;
	}

	/**
	 * Timestamps the {@code value}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} used to compute the {@code value}
	 * @param value the computed digest value
	 * @return {@link TimestampResponseDTO}
	 */
	public TimestampResponseDTO getTimestampResponse(final DigestAlgorithm digestAlgorithm, final byte[] value) {
		Objects.requireNonNull(tspSource, "TSPSource must be not null!");
		LOG.info("Timestamp request in process...");
		Objects.requireNonNull(digestAlgorithm, "digestAlgorithm must be not null!");
		Objects.requireNonNull(value, "value must be not null!");
		TimestampBinary timestampBinary = tspSource.getTimeStampResponse(digestAlgorithm, value);
		if (timestampBinary != null && Utils.isArrayNotEmpty(timestampBinary.getBytes())) {
			LOG.info("Timestamp is obtained.");
			return toTimestampResponseDTO(timestampBinary);
		}
		throw new DSSRemoteServiceException("The obtained TimestampToken response is null or empty!");
	}
	
	private TimestampResponseDTO toTimestampResponseDTO(TimestampBinary timestampBinary) {
		TimestampResponseDTO timestampDTO = new TimestampResponseDTO();
		timestampDTO.setBinaries(timestampBinary.getBytes());
		return timestampDTO;
	}

}
