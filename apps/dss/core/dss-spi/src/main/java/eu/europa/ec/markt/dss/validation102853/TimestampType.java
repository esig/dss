/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853;

/**
 * Source of the timestamp
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1824 $ - $Date: 2013-03-28 15:57:23 +0100 (Thu, 28 Mar 2013) $
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
