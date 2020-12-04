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
package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * Builds data to be timestamped
 */
public interface TimestampDataBuilder {
	
	/**
	 * Returns the content timestamp data (timestamped or to be).
	 *
	 * @param timestampToken {@link TimestampToken}
	 * @return {@code DSSDocument} representing the canonicalized data to be timestamped
	 */
	DSSDocument getContentTimestampData(final TimestampToken timestampToken);

	/**
	 * Returns the data (signature value) that was timestamped by the SignatureTimeStamp for the given timestamp.
	 *
	 * @param timestampToken {@link TimestampToken}
	 * @return {@code DSSDocument} representing the canonicalized data to be timestamped
	 */
	DSSDocument getSignatureTimestampData(final TimestampToken timestampToken);

	/**
	 * Returns the data to be time-stamped. The data contains the digital signature (XAdES example: ds:SignatureValue
	 * element), the signature time-stamp(s) present in the AdES-T form, the certification path references and the
	 * revocation status references.
	 *
	 * @param timestampToken
	 *            {@link TimestampToken} or null during the creation process
	 * @return {@code DSSDocument} representing the canonicalized data to be timestamped
	 */
	DSSDocument getTimestampX1Data(final TimestampToken timestampToken);

	/**
	 * Returns the data to be time-stamped which contains the concatenation of CompleteCertificateRefs and
	 * CompleteRevocationRefs elements (XAdES example).
	 *
	 * @return {@code DSSDocument} representing the canonicalized data to be timestamped
	 */
	DSSDocument getTimestampX2Data(final TimestampToken timestampToken);
	
	/**
	 * Archive timestamp seals the data of the signature in a specific order. We need to retrieve the data for each
	 * timestamp.
	 *
	 * @param timestampToken
	 *            {@link TimestampToken} null when adding a new archive timestamp
	 * @return {@code DSSDocument} representing the canonicalized data to be timestamped
	 */
	DSSDocument getArchiveTimestampData(final TimestampToken timestampToken);

}
