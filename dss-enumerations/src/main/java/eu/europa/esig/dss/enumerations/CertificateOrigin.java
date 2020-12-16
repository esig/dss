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
 * Possible origin types for a certificate
 */
public enum CertificateOrigin {

	/** Certificates extracted from KeyInfo element, XAdES specific */
	KEY_INFO,

	/** Certificates extracted from a signed attribute (CAdES) */
	SIGNED_DATA,

	/** Certificates extracted from CertificateValues element */
	CERTIFICATE_VALUES,

	/** Certificates extracted from AttrAuthoritiesCertValues element, XAdES specific */
	ATTR_AUTHORITIES_CERT_VALUES,

	/** Certificates extracted from TimeStampValidationData element */
	TIMESTAMP_VALIDATION_DATA,

	/** Certificates extracted from DSS dictionary, PAdES specific */
	DSS_DICTIONARY,

	/** Certificates extracted from VRI dictionary, PAdES specific */
	VRI_DICTIONARY,

	/** Certificates extracted from an OCSP Response */
	BASIC_OCSP_RESP

}
