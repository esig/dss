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
package eu.europa.esig.dss.enumerations;

import java.util.ArrayList;
import java.util.List;

/**
 * Type of the timestamp
 *
 */
public enum TimestampType {
	
	// CAdES: id-aa-ets-contentTimestamp
	CONTENT_TIMESTAMP(true, false, false, false),
	
	// XAdES: AllDataObjectsTimestamp
	ALL_DATA_OBJECTS_TIMESTAMP(true, false, false, false),
	
	// XAdES: IndividualDataObjectsTimeStamp
	INDIVIDUAL_DATA_OBJECTS_TIMESTAMP(true, false, false, false),
	
	// CAdES: id-aa-signatureTimeStampToken, XAdES: SignatureTimeStamp
	SIGNATURE_TIMESTAMP(false, true, false, false),
	
	// CAdES: id-aa-ets-certCRLTimestamp, XAdES: RefsOnlyTimeStamp
	VALIDATION_DATA_REFSONLY_TIMESTAMP(false, false, true, false),
	
	// CAdES: id-aa-ets-escTimeStamp, XAdES: SigAndRefsTimeStamp
	VALIDATION_DATA_TIMESTAMP(false, true, true, false),
	
	// CAdES: id-aa-ets-archiveTimestamp, XAdES: ArchiveTimeStamp, PAdES-LTV, "document timestamp"
	ARCHIVE_TIMESTAMP(false, true, true, true);
	
	/* TRUE if the timestamp is a Content timestamp */
	private boolean contentTimestamp;
	
	/* TRUE if the timestamp covers a Signature */
	private boolean coversSignarture;

	/* TRUE if the timestamp covers a ValidationData (certificates or revocation) */
	private boolean coversValidationData;
	
	/* TRUE if the timestamp is an Archival one */
	private boolean archivalTimestamp;
	
	TimestampType(boolean contentTimestamp, boolean coversSignature, boolean coversValidationData, boolean archivalTimestamp) {
		this.contentTimestamp = contentTimestamp;
		this.coversSignarture = coversSignature;
		this.coversValidationData = coversValidationData;
		this.archivalTimestamp = archivalTimestamp;
	}
	
	public boolean isContentTimestamp() {
		return contentTimestamp;
	}
	
	public boolean isSignatureTimestamp() {
		return SIGNATURE_TIMESTAMP.equals(this);
	}
	
	public boolean coversSignature() {
		return coversSignarture;
	}
	
	public boolean coversValidationData() {
		return coversValidationData;
	}
	
	public boolean isArchivalTimestamp() {
		return archivalTimestamp;
	}
	
	/**
	 * Returns an array of all available content timestamps
	 * @return array of content {@link TimestampType}
	 */
	public static TimestampType[] getContentTimestampTypes() {
		List<TimestampType> contentTimestamps = new ArrayList<>();
		for (TimestampType timestampType : values()) {
			if (timestampType.isContentTimestamp()) {
				contentTimestamps.add(timestampType);
			}
		}
		return contentTimestamps.toArray(new TimestampType[contentTimestamps.size()]);
	}
	
	/**
	 * Compares this TimestampType with the provided {@code timestampType}
	 * Must be in the order: Content -> Signature -> ValidationData -> Archival
	 * 
	 * @param timestampType {@link TimestampType} to compare with
	 * @return TRUE if the this timestampType must follow before the provided {@code timestampType}, FALSE otehrwise
	 */
	public int compare(TimestampType timestampType) {
		if (this.isContentTimestamp() && !timestampType.isContentTimestamp()) {
			return -1;
		} else if (!this.isContentTimestamp() && timestampType.isContentTimestamp()) {
			return 1;
		} else if (this.isSignatureTimestamp() && !timestampType.isSignatureTimestamp()) {
			return -1;
		} else if (!this.isSignatureTimestamp() && timestampType.isSignatureTimestamp()) {
			return 1;
		} else if (!this.isArchivalTimestamp() && timestampType.isArchivalTimestamp()) {
			return -1;
		} else if (this.isArchivalTimestamp() && !timestampType.isArchivalTimestamp()) {
			return 1;
		}
		return 0;
	}

}
