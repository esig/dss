package eu.europa.ec.markt.dss.validation102853;

/**
 * This class represents
 */
public class TimestampInclude {

    private String uri;
    private boolean referencedData;

	public TimestampInclude() {}

    public TimestampInclude(String uri, String referencedData) {
        this.uri = uri;
        this.referencedData = Boolean.parseBoolean(referencedData);
    }

    public String getURI() {
        return uri;
    }

    public void setURI(String uri) {
        this.uri = uri;
    }

    public boolean isReferencedData() {
        return referencedData;
    }

    public void setReferencedData(boolean referencedData) {
        this.referencedData = referencedData;
    }
}
