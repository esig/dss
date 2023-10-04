package eu.europa.esig.dss.pki.jaxb.property;

/**
 * Contains a list of JAXB PKI properties
 *
 */
public final class PKIJaxbProperties {

    //TODO add to configuration file
    public static final String CUSTOM_URL_PREFIX = "custom/";
    public static final String EXTENDED_URL_PREFIX = "extended/";
    public static final String EMPTY_URL_PREFIX = "";
    public static final String CRL_EXTENSION = ".crl";
    public static final String CRL_PATH = "crl/";
    public static final String CRT_EXTENSION = ".crt";
    public static final String CRT_PATH = "crt/";
    public static final String OCSP_PATH = "ocsp/";
    public static final String PATTERN = "glob:**/pki/*.xml";
    public static final String XML_FOLDER = "pki";
    public static final String PKI_FACTORY_KEYSTORE_PASSWORD = "pki.factory.keystore.password";
    public static final String PASSWORD = PropertiesLoader.getProperty(PKI_FACTORY_KEYSTORE_PASSWORD);

    public static final String PKI_FACTORY_HOST = "pki.factory.host";
    public static final String HOST = PropertiesLoader.getProperty(PKI_FACTORY_HOST);

    public static final String PKI_FACTORY_COUNTRY = "pki.factory.country";
    public static final String country = PropertiesLoader.getProperty(PKI_FACTORY_COUNTRY, "CC");

    public static final String PKI_FACTORY_ORGANISATION = "pki.factory.organisation";
    public static final String organisation = PropertiesLoader.getProperty(PKI_FACTORY_ORGANISATION, "Organization");

    public static final String PKI_FACTORY_ORGANISATION_UNIT = "pki.factory.organisation.unit";
    public static final String organisationUnit = PropertiesLoader.getProperty(PKI_FACTORY_ORGANISATION_UNIT, "CERT FOR TEST");

}
