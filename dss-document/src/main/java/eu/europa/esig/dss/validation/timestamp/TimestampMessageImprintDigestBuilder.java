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

import eu.europa.esig.dss.model.DSSMessageDigest;

/**
 * Builds message-imprint digest to be timestamped
 *
 */
public interface TimestampMessageImprintDigestBuilder {
	
	/**
	 * Returns the content timestamp message-imprint digest (timestamped or to be).
	 *
	 * @return {@link DSSMessageDigest} representing the message digest on canonicalized data to be timestamped
	 */
	DSSMessageDigest getContentTimestampMessageDigest();

	/**
	 * Returns the message-imprint digest on data (signature value) that was timestamped
	 * by the SignatureTimeStamp for the given timestamp.
	 *
	 * @return {@link DSSMessageDigest} representing the message-digest on canonicalized data to be timestamped
	 */
	DSSMessageDigest getSignatureTimestampMessageDigest();

	/**
	 * Returns the message-imprint digest to be time-stamped. The data used to create digest contains
	 * the digital signature (XAdES example: ds:SignatureValue element), the signature time-stamp(s) present
	 * in the AdES-T form, the certification path references and the revocation status references.
	 *
	 * @return {@link DSSMessageDigest} representing the message digest on canonicalized data to be timestamped
	 */
	DSSMessageDigest getTimestampX1MessageDigest();

	/**
	 * Returns the data to be time-stamped which contains the concatenation of CompleteCertificateRefs and
	 * CompleteRevocationRefs elements (XAdES example).
	 *
	 * @return {@link DSSMessageDigest} representing the message digest on canonicalized data to be timestamped
	 */
	DSSMessageDigest getTimestampX2MessageDigest();
	
	/**
	 * Archive timestamp seals the data of the signature in a specific order.
	 * We need to retrieve the data for each timestamp.
	 *
	 * @return {@link DSSMessageDigest} representing the message digest on canonicalized data to be timestamped
	 */
	DSSMessageDigest getArchiveTimestampMessageDigest();

}
