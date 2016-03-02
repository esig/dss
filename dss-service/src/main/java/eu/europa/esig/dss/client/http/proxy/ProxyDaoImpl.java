package eu.europa.esig.dss.client.http.proxy;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class ProxyDaoImpl implements ProxyDao {

	protected Map<ProxyKey, ProxyPreference> proxyPreferences = new HashMap<ProxyKey, ProxyPreference>();

	public void setHttpsHost(String httpsHost) {
		update(ProxyKey.HTTPS_HOST, httpsHost);
	}

	public void setHttpsPort(String httpsPort) {
		update(ProxyKey.HTTPS_PORT, httpsPort);
	}

	public void setHttpsUser(String httpsUser) {
		update(ProxyKey.HTTPS_USER, httpsUser);
	}

	public void setHttpsPassword(String httpsPassword) {
		update(ProxyKey.HTTPS_PASSWORD, httpsPassword);
	}

	public void setHttpsExclude(String httpsExclude) {
		update(ProxyKey.HTTPS_EXCLUDE, httpsExclude);
	}

	public void setHttpsEnable(String httpsEnable) {
		update(ProxyKey.HTTPS_ENABLED, httpsEnable);
	}

	public void setHttpHost(String httpHost) {
		update(ProxyKey.HTTP_HOST, httpHost);
	}

	public void setHttpPort(String httpPort) {
		update(ProxyKey.HTTP_PORT, httpPort);
	}

	public void setHttpUser(String httpUser) {
		update(ProxyKey.HTTP_USER, httpUser);
	}

	public void setHttpPassword(String httpPassword) {
		update(ProxyKey.HTTP_PASSWORD, httpPassword);
	}

	public void setHttpExclude(String httpExclude) {
		update(ProxyKey.HTTP_EXCLUDE, httpExclude);
	}

	public void setHttpEnable(String httpEnable) {
		update(ProxyKey.HTTP_ENABLED, httpEnable);
	}

	private void update(ProxyKey key, String value) {
		ProxyPreference proxyPreference = proxyPreferences.get(key);
		if (proxyPreference == null) {
			proxyPreference = new ProxyPreference(key, value);
			proxyPreferences.put(key, proxyPreference);
		} else {
			proxyPreference.setValue(value);
		}
	}

	@Override
	public ProxyPreference get(ProxyKey id) {
		return proxyPreferences.get(id);
	}

	@Override
	public Collection<ProxyPreference> getAll() {
		return proxyPreferences.values();
	}

	@Override
	public void update(ProxyPreference entity) {
		proxyPreferences.put(entity.getProxyKey(), entity);
	}

}
