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
package eu.europa.esig.dss.x509;

/**
 * Source of the timestamp
 *
 */
public enum TimestampType {

	CONTENT_TIMESTAMP, // CAdES: id-aa-ets-contentTimestamp
	ALL_DATA_OBJECTS_TIMESTAMP, //XAdES: AllDataObjectsTimestamp
	INDIVIDUAL_DATA_OBJECTS_TIMESTAMP, // XAdES: IndividualDataObjectsTimeStamp
	SIGNATURE_TIMESTAMP, // CAdES: id-aa-signatureTimeStampToken, XAdES: SignatureTimeStamp
	VALIDATION_DATA_REFSONLY_TIMESTAMP, // CAdES: id-aa-ets-certCRLTimestamp, XAdES: RefsOnlyTimeStamp
	VALIDATION_DATA_TIMESTAMP, // CAdES: id-aa-ets-escTimeStamp, XAdES: SigAndRefsTimeStamp
	ARCHIVE_TIMESTAMP // CAdES: id-aa-ets-archiveTimestamp, XAdES: ArchiveTimeStamp, PAdES-LTV "document timestamp"
}
