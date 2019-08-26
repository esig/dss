module jpms_dss_crl_parser_x509crl {
    requires jpms_dss_crl_parser;
    provides eu.europa.esig.dss.crl.ICRLUtils with eu.europa.esig.dss.crl.x509.impl.CRLUtilsX509CRLImpl;
}