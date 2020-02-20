package eu.europa.esig.dss.jades;

/**
 * ETSI TS 119 182-1 V0.0.2
 */
public final class JAdESHeaderParameterNames {

	/**
	 * Claimed signing time
	 */
	public static final String SIG_T = "sigT";

	/**
	 * X509 certificate digest
	 */
	public static final String X5T_O = "x5t#o";

	/**
	 * Digest algorithm and value
	 */
	public static final String DIG_ALG_VAL = "digAlgVal";
	/**
	 * Digest algorithm
	 */
	public static final String DIG_ALG = "digAlg";

	/**
	 * Digest value
	 */
	public static final String DIG_VAL = "digVal";

	/**
	 * Signer commitment
	 */
	public static final String SR_CM = "srCm";

	/**
	 * Commitment Id
	 */
	public static final String COMM_ID = "commId";

	/**
	 * Signature production place
	 */
	public static final String SIG_PL = "sigPl";

	/**
	 * City
	 */
	public static final String CITY = "city";

	/**
	 * Street and address
	 */
	public static final String STR_ADDR = "strAddr";

	/**
	 * State and province
	 */
	public static final String STAT_PROV = "statProv";

	/**
	 * Postal code
	 */
	public static final String POST_CODE = "postCode";

	/**
	 * Country
	 */
	public static final String COUNTRY = "country";

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
	public static final String HASH_PSP = "hashPSp";

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
	public static final String TST_TOKENS = "tsTokens";
	
	/**
	 * Value (i.e. Timestamp base64 value)
	 */
	public static final String VAL = "val";

}
