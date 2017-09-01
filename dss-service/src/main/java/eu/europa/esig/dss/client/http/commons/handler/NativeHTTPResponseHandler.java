package eu.europa.esig.dss.client.http.commons.handler;

import java.net.HttpURLConnection;

public interface NativeHTTPResponseHandler {

    void handle(HttpURLConnection con) throws Exception;

    byte[] handle(byte[] response) throws Exception;

}
