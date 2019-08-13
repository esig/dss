module jpms_dss_utils_apache_commons {
    requires jpms_dss_utils;
    provides eu.europa.esig.dss.utils.IUtils with eu.europa.esig.dss.utils.apache.impl.ApacheCommonsUtils;
}