/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.service.http.commons;

import java.io.Serializable;

/**
 * This object defines a configuration details for HTTP connection to the given host
 *
 */
public class HostConnection implements Serializable {

    private static final long serialVersionUID = -7172356669516643532L;

    /** The name of the remote host */
    private String host;

    /** The port of the host */
    private int port = -1;

    /** Authentication scheme */
    private String scheme;

    /** The realm of the host */
    private String realm;

    /**
     * Empty constructor
     */
    public HostConnection() {
    }

    /**
     * Constructor with host name and port
     *
     * @param host {@link String}
     * @param port integer
     */
    public HostConnection(String host, int port) {
        this(host, port, null);
    }

    /**
     * Constructor with host name, port and authentication scheme
     *
     * @param host {@link String}
     * @param port integer
     * @param scheme {@link String}
     */
    public HostConnection(String host, int port, String scheme) {
        this(host, port, scheme, null);
    }

    /**
     * Complete constructor
     *
     * @param host {@link String}
     * @param port integer
     * @param scheme {@link String}
     * @param realm {@link String}
     */
    public HostConnection(String host, int port, String scheme, String realm) {
        this.host = host;
        this.port = port;
        this.scheme = scheme;
        this.realm = realm;
    }

    /**
     * Gets the host name
     *
     * @return {@link String}
     */
    public String getHost() {
        return host;
    }

    /**
     * Sets the host name
     *
     * @param host {@link String}
     */
    public void setHost(String host) {
        this.host = host;
    }

    /**
     * Gets the host port
     *
     * @return integer
     */
    public int getPort() {
        return port;
    }

    /**
     * Sets the host port
     *
     * Default : -1 (any port)
     *
     * @param port integer value
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Gets the authentication scheme
     *
     * @return {@link String}
     */
    public String getScheme() {
        return scheme;
    }

    /**
     * Sets the authentication scheme
     *
     * @param scheme {@link String}
     */
    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    /**
     * Gets the realm
     *
     * @return {@link String}
     */
    public String getRealm() {
        return realm;
    }

    /**
     * Sets the realm
     *
     * @param realm {@link String}
     */
    public void setRealm(String realm) {
        this.realm = realm;
    }

}
