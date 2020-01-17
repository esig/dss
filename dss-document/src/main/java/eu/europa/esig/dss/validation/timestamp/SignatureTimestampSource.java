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

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.ListCRLSource;
import eu.europa.esig.dss.validation.ListOCSPSource;

public interface SignatureTimestampSource extends Serializable {
	
	List<TimestampToken> getContentTimestamps();
	
	List<TimestampToken> getSignatureTimestamps();
	
	List<TimestampToken> getTimestampsX1();
	
	List<TimestampToken> getTimestampsX2();
	
	List<TimestampToken> getArchiveTimestamps();
	
	List<TimestampToken> getDocumentTimestamps();
	
	List<TimestampToken> getAllTimestamps();
	
	/**
	 * This method allows to add an external timestamp. The given timestamp must be processed before.
	 * 
	 * @param timestamp
	 *            the timestamp token
	 */
	void addExternalTimestamp(TimestampToken timestamp);
	
	/**
	 * Returns a map between all found timestamps and their certificates
	 * @param skipLastArchiveTimestamp
	 *            in case if the last Archive Timestamp is not needed to be returned
	 * @return a map between timestamp-id and list of related {@link CertificateToken}s
	 */
	Map<String, List<CertificateToken>> getCertificateMapWithinTimestamps(boolean skipLastArchiveTimestamp);
	
	/**
	 * Returns a list of all found certificates in the timestamps
	 * @return a list of {@link CertificateToken}s
	 */
	List<CertificateToken> getCertificates();
	
	/**
	 * Returns a merged {@code ListCRLSource} of all embedded timestamp CRL sources
	 * 
	 * @return {@link ListCRLSource}
	 */
	ListCRLSource getTimestampCRLSources();
	
	/**
	 * Returns a merged {@code ListOCSPSource} of all embedded timestamp OCSP
	 * sources
	 * 
	 * @return {@link ListOCSPSource}
	 */
	ListOCSPSource getTimestampOCSPSources();

}
