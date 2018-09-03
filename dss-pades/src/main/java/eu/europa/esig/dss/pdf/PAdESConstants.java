package eu.europa.esig.dss.pdf;

/**
 * This class defines the DSS dictionary constants.
 */
public final class PAdESConstants {

	public static final String SIGNATURE_TYPE = "Sig";
	public static final String SIGNATURE_DEFAULT_FILTER = "Adobe.PPKLite";
	public static final String SIGNATURE_DEFAULT_SUBFILTER = "ETSI.CAdES.detached";

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
