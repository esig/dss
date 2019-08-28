module jpms_dss_utils_apache_commons {
    requires jpms_dss_utils;
    
    requires org.apache.commons.collections4;
    requires org.apache.commons.lang3;
    requires org.apache.commons.codec;
    requires org.apache.commons.io;
    
    provides eu.europa.esig.dss.utils.IUtils with eu.europa.esig.dss.utils.apache.impl.ApacheCommonsUtils;
}