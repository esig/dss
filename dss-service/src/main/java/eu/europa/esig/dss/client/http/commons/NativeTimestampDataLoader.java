package eu.europa.esig.dss.client.http.commons;

public class NativeTimestampDataLoader extends NativeCommonsDataLoader {
    public static final String TIMESTAMP_QUERY_CONTENT_TYPE = "application/timestamp-query";

    public NativeTimestampDataLoader() {
        super("application/timestamp-query");
    }

    public void setContentType(String contentType) {
    }
}
