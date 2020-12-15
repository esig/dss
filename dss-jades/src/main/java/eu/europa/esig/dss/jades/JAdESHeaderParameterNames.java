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
package eu.europa.esig.dss.jades;

/**
 * Defines a list of JAdES header names as in ETSI TS 119 182-1
 */
public final class JAdESHeaderParameterNames {
	
	private JAdESHeaderParameterNames() {
	}

	/**
	 * Claimed signing time
	 */
	public static final String SIG_T = "sigT";

	/**
	 * X509 certificate digest
	 */
	public static final String X5T_O = "x5t#o";

	/**
	 * X509 certificate digests
	 */
	public static final String SIG_X5T_S = "sigX5ts";

	/**
	 * Digest algorithm
	 */
	public static final String DIG_ALG = "digAlg";

	/**
	 * Digest value
	 */
	public static final String DIG_VAL = "digVal";

	/**
	 * Signer commitments
	 */
	public static final String SR_CMS = "srCms";

	/**
	 * Commitment Id
	 */
	public static final String COMM_ID = "commId";

	/**
	 * Signature production place
	 */
	public static final String SIG_PL = "sigPl";

	/**
	 * Country address
	 */
	public static final String ADDRESS_COUNTRY = "addressCountry";

	/**
	 * Locality (City) address
	 */
	public static final String ADDRESS_LOCALITY = "addressLocality";

	/**
	 * Region (state and province) address
	 */
	public static final String ADDRESS_REGION = "addressRegion";

	/**
	 * Post office box number
	 */
	public static final String POST_OFFICE_BOX_NUMBER = "postOfficeBoxNumber";

	/**
	 * Postal code
	 */
	public static final String POSTAL_CODE = "postalCode";

	/**
	 * Street address
	 */
	public static final String STREET_ADDRESS = "streetAddress";

	/**
	 * Q Arrays (used for signed assertions and claimed)
	 */
	public static final String Q_ARRAYS = "qArrays";

	/**
	 * Media type
	 */
	public static final String MEDIA_TYPE = "mediaType";

	/**
	 * Values used for Q Arrays
	 */
	public static final String Q_VALS = "qVals";

	/**
	 * Signer attributes
	 */
	public static final String SR_ATS = "srAts";

	/**
	 * Claimed
	 */
	public static final String CLAIMED = "claimed";

	/**
	 * Certified
	 */
	public static final String CERTIFIED = "certified";

	/**
	 * X509 Attribute certificate
	 */
	public static final String X509_ATTR_CERT = "x509AttrCert";

	/**
	 * Other attribute certificate
	 */
	public static final String OTHER_ATTR_CERT = "otherAttrCert";

	/**
	 * Signed assertions
	 */
	public static final String SIGNED_ASSERTIONS = "signedAssertions";

	/**
	 * Signed data time-stamp
	 */
	public static final String ADO_TST = "adoTst";

	/**
	 * Signature policy identifier
	 */
	public static final String SIG_PID = "sigPId";
	
	/**
	 * Id
	 */
	public static final String ID = "id";

	/**
	 * Hash algo and value
	 */
	public static final String HASH_AV = "hashAV";

	/**
	 * Hash policy is aligned to a specification
	 */
	public static final String DIG_PSP = "digPSp";

	/**
	 * Signature policy qualifiers
	 */
	public static final String SIG_PQUALS = "sigPQuals";
	
	/**
	 * Signature policy URL qualifier
	 */
	public static final String SP_URI = "spURI";
	
	/**
	 * Signature policy User Notice qualifier
	 */
	public static final String SP_USER_NOTICE = "spUserNotice";
	
	/**
	 * Notice references
	 */
	public static final String NOTICE_REF = "noticeRef";
	
	/**
	 * Organization
	 */
	public static final String ORGANTIZATION = "organization";
	
	/**
	 * Notice numbers
	 */
	public static final String NOTICE_NUMBERS = "noticeNumbers";
	
	/**
	 * Explicit text
	 */
	public static final String EXPL_TEXT = "explText";
	
	/**
	 * Signature policy Document Specification qualifier
	 */
	public static final String SP_DSPEC = "spDSpec";
	
	/**
	 * Signed data
	 */
	public static final String SIG_D = "sigD";
	
	/**
	 * Signed data referencing mechanism URI
	 */
	public static final String M_ID = "mId";
	
	/**
	 * Signed data references
	 */
	public static final String PARS = "pars";

	/**
	 * Signed data digest algorithm identifier
	 */
	public static final String HASH_M = "hashM";

	/**
	 * Array of signed data digest algorithm values (hashes)
	 */
	public static final String HASH_V = "hashV";

	/**
	 * Array of signed data types (see 'cty')
	 */
	public static final String CTYS = "ctys";
	
	/**
	 * Description
	 */
	public static final String DESC = "desc";
	
	/**
	 * Document references
	 */
	public static final String DOC_REFS = "docRefs";
	
	/**
	 * Canonicalization algorithm
	 */
	public static final String CANON_ALG = "canonAlg";
	
	/**
	 * Timestamp tokens array
	 */
	public static final String TST_TOKENS = "tstTokens";

	/**
	 * Encoding (eg : DER,...)
	 */
	public static final String ENCODING = "encoding";

	/**
	 * Value (i.e. Timestamp base64 value)
	 */
	public static final String VAL = "val";

	/**
	 * ETSI Unsigned properties
	 */
	public static final String ETSI_U = "etsiU";

	/**
	 * Signature timestamp
	 */
	public static final String SIG_TST = "sigTst";

	/**
	 * Certificate Values
	 */
	public static final String X_VALS = "xVals";

	/**
	 * Certificate Values of Attribute Authorities
	 */
	public static final String AX_VALS = "axVals";

	/**
	 * Revocation Values
	 */
	public static final String R_VALS = "rVals";

	/**
	 * Revocation Values of Attribute Authorities
	 */
	public static final String AR_VALS = "arVals";

	/**
	 * CRL Values
	 */
	public static final String CRL_VALS = "crlVals";

	/**
	 * OCSP Values
	 */
	public static final String OCSP_VALS = "ocspVals";

	/**
	 * Other values
	 */
	public static final String OTHER_VALS = "otherVals";

	/**
	 * X.509 Certificate
	 */
	public static final String X509_CERT = "x509Cert";

	/**
	 * Other certificate
	 */
	public static final String OTHER_CERT = "otherCert";

	/**
	 * Certificate References
	 */
	public static final String X_REFS = "xRefs";

	/**
	 * References to certificates of Attribute Authorities
	 */
	public static final String AX_REFS = "axRefs";

	/**
	 * Revocation References
	 */
	public static final String R_REFS = "rRefs";

	/**
	 * References to revocations of Attribute Authorities
	 */
	public static final String AR_REFS = "arRefs";

	/**
	 * CRL References
	 */
	public static final String CRL_REFS = "crlRefs";

	/**
	 * OCSP References
	 */
	public static final String OCSP_REFS = "ocspRefs";

	/**
	 * OCSP Id
	 */
	public static final String OCSP_ID = "ocspId";

	/**
	 * OCSP Response production time
	 */
	public static final String PRODUCED_AT = "producedAt";

	/**
	 * OCSP Responder id
	 */
	public static final String RESPONDER_ID = "responderId";

	/**
	 * OCSP Responder id - by name
	 */
	public static final String BY_NAME = "byName";

	/**
	 * OCSP Responder id - by key
	 */
	public static final String BY_KEY = "byKey";

	/**
	 * CRL Id
	 */
	public static final String CRL_ID = "crlId";

	/**
	 * CRL issuer
	 */
	public static final String ISSUER = "issuer";

	/**
	 * CRL issue time
	 */
	public static final String ISSUE_TIME = "issueTime";

	/**
	 * CRL Number
	 */
	public static final String NUMBER = "number";
	
	/**
	 * Timestamp Validation Data
	 */
	public static final String TST_VD = "tstVd";

	/**
	 * Shows if TST Validation Data covers a JWS Payload or not
	 */
	public static final String ON_JWSP = "onJWSP";

	/**
	 * Archive TimeStamp
	 */
	public static final String ARC_TST = "arcTst";
	
	/**
	 * Signature and References Timestamp
	 */
	public static final String SIG_R_TST = "sigRTst";

	/**
	 * References Timestamp
	 */
	public static final String RFS_TST = "rfsTst";

	/**
	 * Counter Signature
	 */
	public static final String C_SIG = "cSig";
	
	/**
	 * Signature Policy Store 
	 */
	public static final String SIG_PST = "sigPSt";

	/**
	 * Signature policy document
	 */
	public static final String SIG_POL_DOC = "sigPolDoc";

}
