package eu.europa.esig.dss.pki.jaxb.property;

/**
 * Contains a list of JAXB PKI properties
 *
 */
public final class PKIJaxbProperties {

    /** PKI Factory Host Url (for example: http://dss.nowina.lu/pki-factory/) */
    public static final String PKI_FACTORY_HOST = PropertiesLoader.getProperty("pki.factory.host");

    /** Two-letters country code (for example: LU) */
    public static final String PKI_FACTORY_COUNTRY = PropertiesLoader.getProperty("pki.factory.country", "CC");

    /** Organization name(for example: Nowina Solutions) */
    public static final String PKI_FACTORY_ORGANISATION = PropertiesLoader.getProperty("pki.factory.organisation", "Organization");

    /** Organization unit name (for example: PKI-Test) */
    public static final String PKI_FACTORY_ORGANISATION_UNIT = PropertiesLoader.getProperty("pki.factory.organisation.unit", "CERT FOR TEST");

    /** Extension of a CRL file (for example: ***.crl) */
    public static final String CRL_EXTENSION = PropertiesLoader.getProperty("pki.factory.crl.extension", ".crl");

    /** Preceding path to a CRL file (for example: crl/***) */
    public static final String CRL_PATH = PropertiesLoader.getProperty("pki.factory.crl.path", "crl/");

    /** Extension of a Certificate file (for example: ***.crt) */
    public static final String CERT_EXTENSION = PropertiesLoader.getProperty("pki.factory.cert.extension", ".crt");

    /** Preceding path to a Certificate file (for example: crt/***) */
    public static final String CERT_PATH = PropertiesLoader.getProperty("pki.factory.cert.path", "crt/");

    /** Extension of an OCSP file (for example: ***.ocsp) */
    public static final String OCSP_EXTENSION = PropertiesLoader.getProperty("pki.factory.ocsp.extension", "");

    /** Preceding path to an OCSP file (for example: ocsp/***) */
    public static final String OCSP_PATH = PropertiesLoader.getProperty("pki.factory.ocsp.path", "ocsp/");

}
