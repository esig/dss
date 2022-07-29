package eu.europa.esig.dss.spi.tsl;

/**
 * Contains information extracted from TrustServiceTSLType element
 *
 */
public class ServiceTypeASi {

	/** ServiceTypeIdentifier value */
	private String type;

	/** AdditionalServiceInformation value */
	private String asi;

	/**
	 * Default constructor instantiating object with null values
	 */
	public ServiceTypeASi() {
	}

	/**
	 * Gets the ServiceTypeIdentifier value
	 *
	 * @return {@link String}
	 */
	public String getType() {
		return type;
	}

	/**
	 * Sets the ServiceTypeIdentifier value
	 *
	 * @param type {@link String}
	 */
	public void setType(String type) {
		this.type = type;
	}

	/**
	 * Gets the AdditionalServiceInformation value
	 *
	 * @return {@link String}
	 */
	public String getAsi() {
		return asi;
	}

	/**
	 * Sets the AdditionalServiceInformation value
	 *
	 * @param asi {@link String}
	 */
	public void setAsi(String asi) {
		this.asi = asi;
	}

}
