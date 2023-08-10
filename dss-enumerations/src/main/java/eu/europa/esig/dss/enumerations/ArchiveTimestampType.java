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
 * Different types of archive timestamps.
 *
 */
public enum ArchiveTimestampType {

	/** Default XAdES Archive Timestamp Type */
	XAdES,

	/** ETSI TS 101 903 (XAdES 1.4.1) ArchiveTimeStamp */
	XAdES_141,

	/** Default CAdES Archive Timestamp Type */
	CAdES,

	/** archive-time-stamp-v2 */
	CAdES_V2,

	/** archive-time-stamp-v3 */
	CAdES_V3,
	
	/** Detached timestamp, used for ASiC */
	CAdES_DETACHED,

	/** arcTst */
	JAdES,

	/** DOCUMENT_TIMESTAMP covering a DSS dictionary (revision) */
	PAdES,

	/** XML Evidence Record time-stamp */
	XML_EVIDENCE_RECORD,

	/** ASN.1 Evidence Record time-stamp */
	ASN1_EVIDENCE_RECORD;

}
