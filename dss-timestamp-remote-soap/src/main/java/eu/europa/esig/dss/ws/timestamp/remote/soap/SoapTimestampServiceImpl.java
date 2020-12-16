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
package eu.europa.esig.dss.ws.timestamp.remote.soap;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;
import eu.europa.esig.dss.ws.timestamp.remote.RemoteTimestampService;
import eu.europa.esig.dss.ws.timestamp.remote.soap.client.SoapTimestampService;

/**
 * The SOAP implementation of the timestamping service
 */
public class SoapTimestampServiceImpl implements SoapTimestampService {
	
	private static final long serialVersionUID = 7421969260893851663L;

	/** The timestamp service to use */
	private RemoteTimestampService timestampService;

	/**
	 * Sets the timestamping service
	 *
	 * @param timestampService {@link RemoteTimestampService}
	 */
	public void setTimestampService(RemoteTimestampService timestampService) {
		this.timestampService = timestampService;
	}

	@Override
	public TimestampResponseDTO getTimestampResponse(DigestDTO digest) {
		return timestampService.getTimestampResponse(digest.getAlgorithm(), digest.getValue());
	}

}
