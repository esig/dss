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

	/** 'TU' */
	public static final String TU_DICTIONARY_NAME_VRI = "TU";
	/** 'TS' */
	public static final String TS_DICTIONARY_NAME_VRI = "TS";

	/* Field names */

	/** 'AcroForm' */
	public static final String ACRO_FORM_NAME = "AcroForm";
	/** 'Action' */
	public static final String ACTION_NAME = "Action";
	/** 'F' (Annotation flag) */
	public static final String ANNOT_FLAG = "F";
	/** 'Action' */
	public static final String ANNOTS_NAME = "Annots";
	/** 'AP' (Appearance dictionary) */
	public static final String APPEARANCE_DICTIONARY_NAME = "AP";
	/** 'AS' */
	public static final String AS_NAME = "AS";
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
	/** 'DocMDP' */
	public static final String DOC_MDP_NAME = "DocMDP";
	/** 'DA' (Document-wide appearance) */
	public static final String DOCUMENT_APPEARANCE_NAME = "DA";
	/** 'DR' (Document-wide resources) */
	public static final String DOCUMENT_RESOURCES_NAME = "DR";
	/** 'Extensions' */
	public static final String EXTENSIONS_NAME = "Extensions";
	/** 'FieldMDP' */
	public static final String FIELD_MDP_NAME = "FieldMDP";
	/** 'Fields' */
	public static final String FIELDS_NAME = "Fields";
	/** 'T' (Field name) */
	public static final String FIELD_NAME_NAME = "T";
	/** 'Filter' */
	public static final String FILTER_NAME = "Filter";
	/** 'Font' */
	public static final String FONT_NAME = "Font";
	/** 'ITXT' (iText identifier) */
	public static final String ITEXT_NAME = "ITXT";
	/** 'Location' */
	public static final String LOCATION_NAME = "Location";
	/** 'Lock' */
	public static final String LOCK_NAME = "Lock";
	/** 'Metadata' */
	public static final String METADATA_NAME = "Metadata";
	/** 'Name' */
	public static final String NAME_NAME = "Name";
	/** 'Names' */
	public static final String NAMES_NAME = "Names";
	/** 'OutputIntents' */
	public static final String OUTPUT_INTENTS_NAME = "OutputIntents";
	/** 'Parent' */
	public static final String PARENT_NAME = "Parent";
	/** 'P' (Permissions) */
	public static final String PERMISSIONS_NAME = "P";
	/** 'Perms' */
	public static final String PERMS_NAME = "Perms";
	/** 'PieceInfo' */
	public static final String PIECE_INFO_NAME = "PieceInfo";
	/** 'Reason' */
	public static final String REASON_NAME = "Reason";
	/** 'Reference' */
	public static final String REFERENCE_NAME = "Reference";
	/** 'Root' */
	public static final String ROOT_NAME = "Root";
	/** 'M' (Signing date) */
	public static final String SIGNING_DATE_NAME = "M";
	/** 'SigFieldLock' */
	public static final String SIG_FIELD_LOCK_NAME = "SigFieldLock";
	/** 'SigFlags' */
	public static final String SIG_FLAGS_NAME = "SigFlags";
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
	/** 'V' (Value) */
	public static final String VALUE_NAME = "V";
	/** 'Version' */
	public static final String VERSION_NAME = "Version";

	/* Build properties dictionary */

	/** 'App' (Application software) */
	public static final String APP = "App";

	/** 'Prop_Build' (Build properties) */
	public static final String PROP_BUILD = "Prop_Build";

	/** 'V=1.2' */
	public static final String VERSION_DEFAULT = "1.2";

	/**
	 * Utils class
	 */
	private PAdESConstants() {
		// empty
	}

}
