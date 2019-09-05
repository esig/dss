module jpms_dss_crl_parser_stream {
    requires jpms_dss_crl_parser;
    
	opens org.bouncycastle.provider;
    
    provides eu.europa.esig.dss.crl.ICRLUtils with eu.europa.esig.dss.crl.stream.impl.CRLUtilsStreamImpl;
}