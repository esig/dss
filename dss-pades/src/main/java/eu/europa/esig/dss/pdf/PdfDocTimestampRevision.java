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
package eu.europa.esig.dss.pdf;

import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

/**
 * Signature timestamp representation
 * This class is only used in case of Document Timestamp (not signature-timestamp from CAdES/CMS)
 */
public class PdfDocTimestampRevision extends PdfCMSRevision {

	private static final Logger LOG = LoggerFactory.getLogger(PdfDocTimestampRevision.class);

	private final TimestampToken timestampToken;

	/**
	 * Default constructor to create PdfDocTimestampInfo
	 * 
	 * @param signatureDictionary
	 *            					   the signature dictionary
	 * @param timestampFieldNames
	 *            					   list of signature field names
	 * @param signedContent
	 *                                 the signed data
	 * @param coverCompleteRevision
	 *                                 true if the signature covers all bytes
	 * @param isArchiveTimestamp
	 *                                 true if it is an ArchiveTimestamp
	 */
	public PdfDocTimestampRevision(PdfSignatureDictionary signatureDictionary, List<String> timestampFieldNames, byte[] signedContent,
			boolean coverCompleteRevision, boolean isArchiveTimestamp) {
		super(signatureDictionary, timestampFieldNames, signedContent, coverCompleteRevision);
		try {
			TimestampType timestampType = isArchiveTimestamp ? TimestampType.ARCHIVE_TIMESTAMP : TimestampType.SIGNATURE_TIMESTAMP;
			timestampToken = new PdfTimestampToken(this, timestampType);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Created PdfDocTimestampInfo {} : {}", timestampType, getByteRange());
			}
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	@Override
	public Date getSigningDate() {
		return timestampToken.getGenerationTime();
	}

	public TimestampToken getTimestampToken() {
		return timestampToken;
	}

}
