package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JsonObject;

public class EtsiUComponent extends JAdESAttribute {

	private Object component;
	private boolean base64UrlEncoded;
	private int hashValue;

	public EtsiUComponent(Object component, String headerName, Object value, int order) {
		super(headerName, value);
		this.component = component;
		this.base64UrlEncoded = DSSJsonUtils.isStringFormat(component);
		this.hashValue = component.hashCode() + order; // enforce different values for equal string components
	}

	/**
	 * Gets the attribute in its 'etsiU' member representation
	 * 
	 * @return 'etsiU' array's component
	 */
	public Object getComponent() {
		return component;
	}

	public boolean isBase64UrlEncoded() {
		return base64UrlEncoded;
	}

	public void overwriteValue(Object value) {
		this.value = value;
		this.component = recreateEtsiUComponent(name, value, base64UrlEncoded);
	}

	/**
	 * Returns an 'etsiU' component in the defined representation
	 * 
	 * @param name             {@link String} header name
	 * @param value            object
	 * @param base64UrlEncoded TRUE if base64Url encoded representation, FALSE
	 *                         otherwise
	 * @return 'etsiU' component
	 */
	public Object recreateEtsiUComponent(String name, Object value, boolean base64UrlEncoded) {
		JsonObject jsonObject = new JsonObject();
		jsonObject.put(name, value);
		return base64UrlEncoded ? DSSJsonUtils.toBase64Url(jsonObject) : jsonObject;
	}

	@Override
	public int hashCode() {
		return hashValue;
	}

}
