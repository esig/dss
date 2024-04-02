package eu.europa.esig.dss.service;

import java.io.InputStream;
import java.util.Properties;

public abstract class OnlineSourceTest {

    protected static final String ONLINE_PKI_HOST;


    static {
        try (InputStream is = OnlineSourceTest.class.getResourceAsStream("/service.properties")) {
            Properties props = new Properties();
            props.load(is);
            ONLINE_PKI_HOST = props.getProperty("online.pki.host");
        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize from service.properties", e);
        }
    }

}
