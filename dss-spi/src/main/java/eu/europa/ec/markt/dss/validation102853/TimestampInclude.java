// TODO-Vin (12/09/2014): CopyRight to be added!
package eu.europa.ec.markt.dss.validation102853;

/**
 * This class represents
 */
public class TimestampInclude {

    private String uri;
	// TODO-Vin (12/09/2014): What does it mean?
	private boolean referencedData;

	// TODO-Vin (12/09/2014): Is this constructor useful? Does it make sens?
	public TimestampInclude() {}

	// TODO-Vin (12/09/2014): Comments!
	public TimestampInclude(String uri, String referencedData) {
		this.uri = uri;
		this.referencedData = Boolean.parseBoolean(referencedData);
	}

	// TODO-Vin (12/09/2014): Comments!
    public TimestampInclude(String uri, boolean referencedData) {
        this.uri = uri;
        this.referencedData = referencedData;
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

	// TODO-Vin (12/09/2014): Never used???
	public void setReferencedData(boolean referencedData) {
        this.referencedData = referencedData;
    }
}
