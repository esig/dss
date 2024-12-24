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
package eu.europa.esig.dss.cookbook.example.snippets.ws.soap;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;
import eu.europa.esig.dss.ws.timestamp.remote.soap.SoapTimestampServiceImpl;
import eu.europa.esig.dss.ws.timestamp.remote.soap.client.SoapTimestampService;

public class SoapTimestampServiceSnippet {

    @SuppressWarnings("unused")
    public void demo() throws Exception {
        // tag::demo[]
        // import eu.europa.esig.dss.ws.timestamp.remote.soap.SoapTimestampServiceImpl;
        // import eu.europa.esig.dss.ws.timestamp.remote.soap.client.SoapTimestampService;

        // Initialize the soap client
        SoapTimestampService timestampService = new SoapTimestampServiceImpl();

        // end::demo[]

        // Initialize data to be timestamped (e.g. a document)
        byte[] contentToBeTimestamped = "Hello World!".getBytes();

        // Apply hash-function on the data
        byte[] digestValue = DSSUtils.digest(DigestAlgorithm.SHA256, contentToBeTimestamped);

        // Create an object to be provided to the timestamping service
        // NOTE: ensure that the same DigestAlgorithm is used in both method calls
        DigestDTO digest = new DigestDTO(DigestAlgorithm.SHA256, digestValue);

        // Timestamp the digest
        TimestampResponseDTO timestampResponse = timestampService.getTimestampResponse(digest);
    }

}
