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

	/** Signature type 'Sig' */
	public static final String SIGNATURE_TYPE = "Sig";
	/** Filter 'Adobe.PPKLite' */
	public static final String SIGNATURE_DEFAULT_FILTER = "Adobe.PPKLite";
	/** SubFilter 'ETSI.CAdES.detached' */
	public static final String SIGNATURE_DEFAULT_SUBFILTER = "ETSI.CAdES.detached";
	/** SubFilter 'adbe.pkcs7.detached' */
	public static final String SIGNATURE_PKCS7_SUBFILTER = "adbe.pkcs7.detached";
	/** SubFilter 'adbe.pkcs7.sha1' */
	public static final String SIGNATURE_PKCS7_SHA1_SUBFILTER = "adbe.pkcs7.sha1";

	/** Signature typ 'DocTimeStamp' */
	public static final String TIMESTAMP_TYPE = "DocTimeStamp";
	/** Filter 'Adobe.PPKLite' */
	public static final String TIMESTAMP_DEFAULT_FILTER = "Adobe.PPKLite";
	/** SubFilter 'ETSI.RFC3161' */
	public static final String TIMESTAMP_DEFAULT_SUBFILTER = "ETSI.RFC3161";

	/** 'DSS' */
	public static final String DSS_DICTIONARY_NAME = "DSS";
	/** 'Certs' */
	public static final String CERT_ARRAY_NAME_DSS = "Certs";
	/** 'OCSPs' */
	public static final String OCSP_ARRAY_NAME_DSS = "OCSPs";
	/** 'CRLs' */
	public static final String CRL_ARRAY_NAME_DSS = "CRLs";

	/** 'VRI' */
	public static final String VRI_DICTIONARY_NAME = "VRI";
	/** 'Cert' */
	public static final String CERT_ARRAY_NAME_VRI = "Cert";
	/** 'OCSP' */
	public static final String OCSP_ARRAY_NAME_VRI = "OCSP";
	/** 'CRL' */
	public static final String CRL_ARRAY_NAME_VRI = "CRL";

	/* Field names */

	/** 'Action' */
	public static final String ACTION_NAME = "Action";
	/** 'ByteRange' */
	public static final String BYTE_RANGE_NAME = "ByteRange";
	/** 'Catalog' */
	public static final String CATALOG_NAME = "Catalog";
	/** 'ContactInfo' */
	public static final String CONTACT_INFO_NAME = "ContactInfo";
	/** 'Contents' */
	public static final String CONTENTS_NAME = "Contents";
	/** 'Data' */
	public static final String DATA_NAME = "Data";
	/** 'FieldMDP' */
	public static final String FIELD_MDP_NAME = "FieldMDP";
	/** 'Fields' */
	public static final String FIELDS_NAME = "Fields";
	/** 'T' (Field name) */
	public static final String FIELD_NAME_NAME = "T";
	/** 'Filter' */
	public static final String FILTER_NAME = "Filter";
	/** 'Location' */
	public static final String LOCATION_NAME = "Location";
	/** 'Lock' */
	public static final String LOCK_NAME = "Lock";
	/** 'Name' */
	public static final String NAME_NAME = "Name";
	/** 'P' (Permissions) */
	public static final String PERMISSIONS_NAME = "P";
	/** 'Reason' */
	public static final String REASON_NAME = "Reason";
	/** 'Reference' */
	public static final String REFERENCE_NAME = "Reference";
	/** 'M' (Signing date) */
	public static final String SIGNING_DATE_NAME = "M";
	/** 'SigFieldLock' */
	public static final String SIG_FIELD_LOCK_NAME = "SigFieldLock";
	/** 'SigRef' */
	public static final String SIG_REF_NAME = "SigRef";
	/** 'SubFilter' */
	public static final String SUB_FILTER_NAME = "SubFilter";
	/** 'Type' */
	public static final String TYPE_NAME = "Type";
	/** 'TransformMethod' */
	public static final String TRANSFORM_METHOD_NAME = "TransformMethod";
	/** 'TransformParams' */
	public static final String TRANSFORM_PARAMS_NAME = "TransformParams";
	/** 'UR' (User rights) */
	public static final String UR_NAME = "UR";
	/** 'UR3' (User rights) */
	public static final String UR3_NAME = "UR3";

	/* Field values */

	/** 'V=1.2' */
	public static final String VERSION_DEFAULT = "1.2";

	/**
	 * Utils class
	 */
	private PAdESConstants() {
	}

}
