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

/**
 * This class defines the DSS dictionary constants.
 */
public final class PAdESConstants {

	public static final String SIGNATURE_TYPE = "Sig";
	public static final String SIGNATURE_DEFAULT_FILTER = "Adobe.PPKLite";
	public static final String SIGNATURE_DEFAULT_SUBFILTER = "ETSI.CAdES.detached";
	public static final String SIGNATURE_PKCS7_SUBFILTER = "adbe.pkcs7.detached";
	public static final String SIGNATURE_PKCS7_SHA1_SUBFILTER = "adbe.pkcs7.sha1";

	public static final String TIMESTAMP_TYPE = "DocTimeStamp";
	public static final String TIMESTAMP_DEFAULT_FILTER = "Adobe.PPKLite";
	public static final String TIMESTAMP_DEFAULT_SUBFILTER = "ETSI.RFC3161";

	public static final String DSS_DICTIONARY_NAME = "DSS";
	public static final String CERT_ARRAY_NAME_DSS = "Certs";
	public static final String OCSP_ARRAY_NAME_DSS = "OCSPs";
	public static final String CRL_ARRAY_NAME_DSS = "CRLs";

	public static final String VRI_DICTIONARY_NAME = "VRI";
	public static final String CERT_ARRAY_NAME_VRI = "Cert";
	public static final String OCSP_ARRAY_NAME_VRI = "OCSP";
	public static final String CRL_ARRAY_NAME_VRI = "CRL";

	private PAdESConstants() {
	}

}
