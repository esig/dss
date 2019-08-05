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
package eu.europa.esig.dss.xades.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;

/**
 * This class allows to create a XAdES content-timestamp which covers all documents (AllDataObjectsTimeStamp).
 * 
 */
public class AllDataObjectsTimeStampBuilder {

	private final TSPSource tspSource;
	private final TimestampParameters timestampParameters;

	public AllDataObjectsTimeStampBuilder(TSPSource tspSource, TimestampParameters timestampParameters) {
		this.tspSource = tspSource;
		this.timestampParameters = timestampParameters;
	}

	public TimestampToken build(DSSDocument document) {
		return build(Arrays.asList(document));
	}

	public TimestampToken build(List<DSSDocument> documents) {
		boolean canonicalizationUsed = false;
		byte[] dataToBeDigested = null;

		/*
		 * 1) process the retrieved ds:Reference element according to the reference-processing model of XMLDSIG [1]
		 * clause 4.4.3.2;
		 * 2) if the result is a XML node set, canonicalize it as specified in clause 4.5; and
		 * 3) concatenate the resulting octets to those resulting from previously processed ds:Reference elements in
		 * ds:SignedInfo.
		 */
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			for (DSSDocument document : documents) {
				byte[] binaries = DSSUtils.toByteArray(document);
				if (Utils.isStringNotEmpty(timestampParameters.getCanonicalizationMethod()) && DomUtils.isDOM(binaries)) {
					binaries = DSSXMLUtils.canonicalize(timestampParameters.getCanonicalizationMethod(), binaries);
					canonicalizationUsed = true;
				}
				baos.write(binaries);
			}
			dataToBeDigested = baos.toByteArray();
		} catch (IOException e) {
			throw new DSSException("Unable to compute the data to be digested", e);
		}

		byte[] digestToTimestamp = DSSUtils.digest(timestampParameters.getDigestAlgorithm(), dataToBeDigested);
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(timestampParameters.getDigestAlgorithm(), digestToTimestamp);
		TimestampToken token = new TimestampToken(timeStampResponse, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);

		if (canonicalizationUsed) {
			token.setCanonicalizationMethod(timestampParameters.getCanonicalizationMethod());
		}

		return token;
	}

}
