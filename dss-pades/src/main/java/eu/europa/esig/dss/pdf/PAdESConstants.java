package eu.europa.esig.dss.pdf;

/**
 * This interface defines the DSS dictionary constants.
 */
public interface PAdESConstants {

	String SIGNATURE_TYPE = "Sig";
	String SIGNATURE_DEFAULT_FILTER = "Adobe.PPKLite";
	String SIGNATURE_DEFAULT_SUBFILTER = "ETSI.CAdES.detached";

	String TIMESTAMP_TYPE = "DocTimeStamp";
	String TIMESTAMP_DEFAULT_FILTER = "Adobe.PPKLite";
	String TIMESTAMP_DEFAULT_SUBFILTER = "ETSI.RFC3161";

	String DSS_DICTIONARY_NAME = "DSS";
	String CERT_ARRAY_NAME_DSS = "Certs";
	String OCSP_ARRAY_NAME_DSS = "OCSPs";
	String CRL_ARRAY_NAME_DSS = "CRLs";

	String VRI_DICTIONARY_NAME = "VRI";
	String CERT_ARRAY_NAME_VRI = "Cert";
	String OCSP_ARRAY_NAME_VRI = "OCSP";
	String CRL_ARRAY_NAME_VRI = "CRL";

}
