package eu.europa.esig.dss.client.http.commons.handler;

import java.net.HttpURLConnection;

public interface NativeHTTPConnectionHandler {

    void handle(HttpURLConnection con) throws Exception;

}
