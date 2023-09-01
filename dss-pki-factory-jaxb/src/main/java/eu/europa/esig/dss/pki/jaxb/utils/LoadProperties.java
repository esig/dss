package eu.europa.esig.dss.pki.jaxb.utils;


import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * A utility class to load properties from a properties file named "pki.properties".
 * This class provides a method to retrieve property values based on given keys.
 */
public final class LoadProperties {

    /**
     * The name of the properties file to be loaded.
     */
    public static final String APPLICATION_PROPERTIES = "pki.properties";

    /**
     * Loads properties from the "pki.properties" file located in the classpath.
     *
     * @return A Properties object containing the loaded properties.
     * @throws IOException If an I/O error occurs while loading the properties.
     */
    private static Properties loadProperties() throws IOException {
        Properties configuration = new Properties();
        try (InputStream inputStream = LoadProperties.class.getClassLoader().getResourceAsStream(APPLICATION_PROPERTIES)) {
            configuration.load(inputStream);
        }
        return configuration;
    }

    /**
     * Retrieves the value of a property with the given key from the properties file.
     *
     * @param key          The key of the property to retrieve.
     * @param defaultValue A default value to be returned if the property is not found or empty.
     * @return The value of the property if found, or the defaultValue if the property is not found or empty.
     * @throws RuntimeException If an I/O error occurs while loading the properties.
     */
    public static String getValue(String key, String... defaultValue) {
        Properties conf;
        try {
            conf = loadProperties();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return conf.getProperty(key).equals("") && defaultValue.length > 0 && defaultValue[0] != null ?
                defaultValue[0] : conf.getProperty(key);
    }
}
