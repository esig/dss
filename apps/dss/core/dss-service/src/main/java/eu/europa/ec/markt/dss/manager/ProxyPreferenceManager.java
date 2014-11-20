/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.manager;

import java.util.Collection;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.dao.ProxyDao;
import eu.europa.ec.markt.dss.dao.ProxyKey;
import eu.europa.ec.markt.dss.dao.ProxyPreference;

/**
 * 
 * A proxy preference manager.
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ProxyPreferenceManager {

    private ProxyDao proxyDao;

    /**
     * Get a {@link ProxyPreference} by its enum values.
     * 
     * @param proxyKey
     * @return a preference
     */
    public ProxyPreference get(ProxyKey proxyKey) {
        return getProxyDao().get(proxyKey);
    }

    /**
     * Get the host of the HTTP proxy
     * 
     * @return the host
     */
    public String getHttpHost() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_HOST);
        return preference != null ? preference.getValue() : DSSUtils.EMPTY;
    }

    /**
     * Get the password of HTTPS proxy
     * 
     * @return the password
     */
    public String getHttpPassword() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_PASSWORD);
        return preference != null ? preference.getValue() : DSSUtils.EMPTY;
    }

    /**
     * Get the port of the HTTP proxy
     * 
     * @return the port
     */
    public Long getHttpPort() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_PORT);
        return preference != null ? Long.valueOf(preference.getValue()) : null;
    }

    /**
     * Get the host of the HTTPS proxy
     * 
     * @return the host
     */
    public String getHttpsHost() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_HOST);
        return preference != null ? preference.getValue() : DSSUtils.EMPTY;
    }

    /**
     * Get the password of the HTTPS proxy
     * 
     * @return the password
     */
    public String getHttpsPassword() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_PASSWORD);
        return preference != null ? preference.getValue() : DSSUtils.EMPTY;
    }

    /**
     * Get the port of the HTTPS proxy
     * 
     * @return the port
     */
    public Long getHttpsPort() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_PORT);
        return preference != null ? Long.valueOf(preference.getValue()) : null;
    }

    /**
     * Get the user of the HTTPS proxy
     * 
     * @return the user
     */
    public String getHttpsUser() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_USER);
        return preference != null ? preference.getValue() : DSSUtils.EMPTY;
    }

    /**
     * Get the user for HTTP proxy
     * 
     * @return the user
     */
    public String getHttpUser() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_USER);
        return preference != null ? preference.getValue() : DSSUtils.EMPTY;
    }

    /**
     * Returns true if the HTTP proxy must be enabled.
     * 
     * @return a boolean value
     */
    public boolean isHttpEnabled() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_ENABLED);

        if (preference == null || DSSUtils.isEmpty(preference.getValue())) {
            return false;
        } else {
            return Boolean.valueOf(preference.getValue()).booleanValue();
        }
    }

    /**
     * Returns true if the HTTPS proxy must be enabled.
     * 
     * @return a boolean value
     */
    public boolean isHttpsEnabled() {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_ENABLED);

        if (preference == null || DSSUtils.isEmpty(preference.getValue())) {
            return false;
        } else {
            return Boolean.valueOf(preference.getValue()).booleanValue();
        }

    }

    /**
     * 
     * @return a list of {@link ProxyPreference}
     */
    public Collection<ProxyPreference> list() {
        return getProxyDao().getAll();
    }

    /**
     * 
     * @param enabled
     */
    public void setHttpEnabled(boolean enabled) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_ENABLED);
        preference.setValue(String.valueOf(enabled));
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param host
     */
    public void setHttpHost(String host) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_HOST);
        preference.setValue(host);
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param password
     */
    public void setHttpPassword(String password) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_PASSWORD);
        preference.setValue(password);
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param port
     */
    public void setHttpPort(Long port) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_PORT);
        preference.setValue(port != null ? String.valueOf(port) : DSSUtils.EMPTY);
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param enabled
     */
    public void setHttpsEnabled(boolean enabled) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_ENABLED);
        preference.setValue(String.valueOf(enabled));
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param host
     */
    public void setHttpsHost(String host) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_HOST);
        preference.setValue(host);
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param password
     */
    public void setHttpsPassword(String password) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_PASSWORD);
        preference.setValue(password);
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param port
     */
    public void setHttpsPort(Long port) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_PORT);
        preference.setValue(port != null ? String.valueOf(port) : DSSUtils.EMPTY);
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param user
     */
    public void setHttpsUser(String user) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTPS_USER);
        preference.setValue(user);
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param httpUser
     */
    public void setHttpUser(String httpUser) {
        ProxyPreference preference = getProxyDao().get(ProxyKey.HTTP_USER);
        preference.setValue(httpUser);
        getProxyDao().update(preference);
    }

    /**
     * 
     * @param proxyDao
     */
    public void setProxyDao(ProxyDao proxyDao) {
        this.proxyDao = proxyDao;
    }

    /**
     * Gets the proxyDao
     * @return the proxyDao
     */
    private ProxyDao getProxyDao(){
        if (proxyDao == null){
            throw new IllegalStateException("The proxyDao property must be set to use this class!");
        }
        return proxyDao;
    }
    /**
     * 
     * @param proxyKey
     * @param value
     */
    public void update(ProxyKey proxyKey, String value) {
        switch (proxyKey) {
        case HTTP_ENABLED:
            setHttpEnabled(Boolean.valueOf(value));
            break;
        case HTTP_HOST:
            setHttpHost(value);
            break;
        case HTTP_PASSWORD:
            setHttpPassword(value);
            break;
        case HTTP_PORT:
            // TODO use regex to check if number
            setHttpPort(Long.valueOf(value));
            break;
        case HTTP_USER:
            setHttpUser(value);
            break;
        case HTTPS_ENABLED:
            setHttpsEnabled(Boolean.valueOf(value));
            break;
        case HTTPS_HOST:
            setHttpsHost(value);
            break;
        case HTTPS_PASSWORD:
            setHttpsPassword(value);
            break;
        case HTTPS_PORT:
            // FIXME use regex to check if number
            setHttpsPort(Long.valueOf(value));
            break;
        case HTTPS_USER:
            setHttpsUser(value);
            break;

        }

    }

    /**
     * 
     * @param key
     * @param value
     */
    public void update(String key, String value) {
        update(ProxyKey.fromKey(key), value);
    }

	@Override
	public String toString() {
		return "ProxyPreferenceManager{" +
			  "proxyDao=" + proxyDao +
			  '}';
	}
}
