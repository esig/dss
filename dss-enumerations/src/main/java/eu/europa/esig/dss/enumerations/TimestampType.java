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

/**
 * Type of timestamp
 *
 */
public enum TimestampType {
	
	/** CAdES: id-aa-ets-contentTimestamp, JAdES: adoTst */
	CONTENT_TIMESTAMP(0, false),

	/** XAdES: AllDataObjectsTimestamp */
	ALL_DATA_OBJECTS_TIMESTAMP(0, false),

	/** XAdES: IndividualDataObjectsTimeStamp */
	INDIVIDUAL_DATA_OBJECTS_TIMESTAMP(0, false),

	/** CAdES/PAdES: id-aa-signatureTimeStampToken, XAdES: SignatureTimeStamp, JAdES: sigTst */
	SIGNATURE_TIMESTAMP(1, true),

	/** PAdES: /VRI/TS */
	VRI_TIMESTAMP(1, true),

	/** CAdES: id-aa-ets-certCRLTimestamp, XAdES: RefsOnlyTimeStamp, JAdES: rfsTst */
	VALIDATION_DATA_REFSONLY_TIMESTAMP(2, false),

	/** CAdES: id-aa-ets-escTimeStamp, XAdES: SigAndRefsTimeStamp, JAdES: sigRTst */
	VALIDATION_DATA_TIMESTAMP(2, true),

	/** PAdES-LTV "document timestamp" */
	DOCUMENT_TIMESTAMP(3, true),

	/** CAdES: id-aa-ets-archiveTimestamp, XAdES: ArchiveTimeStamp, JAdES: arcTst */
	ARCHIVE_TIMESTAMP(3, true);
	
	/**
	 * Specifies a presence order of the timestamp in a signature
	 * The following notation is used:
	 * 	0 - content timestamps
	 * 	1 - signature timestamp
	 * 	2 - validation data timestamps
	 * 	3 - archive timestamps
	 */
	private final Integer order;
	
	/* TRUE if the timestamp covers a Signature */
	private final boolean coversSignature;
	
	TimestampType(int order, boolean coversSignature) {
		this.order = order;
		this.coversSignature = coversSignature;
	}
	
	/**
	 * Checks if the timestamp type is a content timestamp
	 * 
	 * @return TRUE if the type is a content timestamp, FALSE otherwise
	 */
	public boolean isContentTimestamp() {
		return 0 == order;
	}

	/**
	 * Checks if the timestamp type is a signature timestamp
	 * 
	 * @return TRUE if the type is a signature timestamp, FALSE otherwise
	 */
	public boolean isSignatureTimestamp() {
		return 1 == order;
	}

	/**
	 * Checks if the timestamp type is a validation data timestamp
	 * 
	 * @return TRUE if the type is a validation data timestamp, FALSE otherwise
	 */
	public boolean isValidationDataTimestamp() {
		return 2 == order;
	}

	/**
	 * Checks if the timestamp type is a document timestamp (used for PAdES)
	 *
	 * @return TRUE if the type is a document timestamp, FALSE otherwise
	 */
	public boolean isDocumentTimestamp() {
		return DOCUMENT_TIMESTAMP == this;
	}

	/**
	 * Checks if the timestamp type is an archive timestamp
	 * 
	 * @return TRUE if the type is an archive timestamp, FALSE otherwise
	 */
	public boolean isArchivalTimestamp() {
		return ARCHIVE_TIMESTAMP == this;
	}
	
	/**
	 * Checks if a timestamp of this type covers a signature
	 * 
	 * @return TRUE if a timestamp of the type covers a signature, FALSE otherwise
	 */
	public boolean coversSignature() {
		return coversSignature;
	}
	
	/**
	 * Compares this TimestampType with the provided {@code timestampType}
	 * Must be in the order: Content - Signature - ValidationData - Archival
	 * 
	 * @param timestampType {@link TimestampType} to compare with
	 * @return TRUE if this timestampType must follow before the provided {@code timestampType}, FALSE otherwise
	 */
	public int compare(TimestampType timestampType) {
		return order.compareTo(timestampType.order);
	}

}
