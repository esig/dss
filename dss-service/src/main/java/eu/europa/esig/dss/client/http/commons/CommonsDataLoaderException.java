package eu.europa.esig.dss.client.http.commons;

import eu.europa.esig.dss.DSSException;

public class CommonsDataLoaderException extends DSSException {

    private int responseCode;
    private byte[] responseContent;

    public CommonsDataLoaderException(String message, int responseCode, byte[] responseContent) {
        super(message);
        this.responseCode = responseCode;
        this.responseContent = responseContent;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public byte[] getResponseContent() {
        return responseContent;
    }
}
