package eu.europa.esig.dss.pki.constant;


import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;


public final class LoadProperties {

    public static final String APPLICATION_PROPERTIES = "pki.properties";

    private static Properties loadProperties() throws IOException {
        Properties configuration = new Properties();
        try (InputStream inputStream = LoadProperties.class.getClassLoader().getResourceAsStream(APPLICATION_PROPERTIES)) {
            configuration.load(inputStream);
        }
        return configuration;
    }

    public static String getValue(String key, String... defaultValue) {
        Properties conf;
        try {
            conf = loadProperties();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return conf.getProperty(key).equals("") && defaultValue[0] != null ? defaultValue[0] : conf.getProperty(key);

    }

}
