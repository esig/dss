package eu.europa.esig.dss.client.http.commons.handler;

public interface NativeHTTPRequestHandler {

    byte[] handle(byte[] content) throws Exception;

}
