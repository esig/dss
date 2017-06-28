package eu.europa.esig.dss.client.http.proxy;

/**
 * This class is a DTO which contains the proxy configuration (HTTP and/or HTTPS)
 */
public class ProxyConfig {

	/* Properties for HTTP Proxy (null if disabled) */
	private ProxyProperties httpProperties;

	/* Properties for HTTPS Proxy (null if disabled) */
	private ProxyProperties httpsProperties;

	public ProxyProperties getHttpProperties() {
		return httpProperties;
	}

	public void setHttpProperties(ProxyProperties httpProperties) {
		this.httpProperties = httpProperties;
	}

	public ProxyProperties getHttpsProperties() {
		return httpsProperties;
	}

	public void setHttpsProperties(ProxyProperties httpsProperties) {
		this.httpsProperties = httpsProperties;
	}

}
