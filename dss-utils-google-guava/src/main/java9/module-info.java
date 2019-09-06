module jpms_dss_utils_google_guava {
    requires jpms_dss_utils;
    requires com.google.common;
    
    provides eu.europa.esig.dss.utils.IUtils with eu.europa.esig.dss.utils.guava.impl.GoogleGuavaUtils;
}