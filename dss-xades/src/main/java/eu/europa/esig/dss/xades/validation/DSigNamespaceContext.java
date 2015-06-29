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
package eu.europa.esig.dss.xades.validation;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.namespace.NamespaceContext;

/**
 *
 */
public class DSigNamespaceContext implements NamespaceContext {

    private Map<String, String> pfxToUri;

    private Map<String, String> uriToPfx;

    DSigNamespaceContext() {

        this.pfxToUri = new HashMap<String, String>();
        this.uriToPfx = new HashMap<String, String>();
    }

    /**
     * Add a prefix to namespace mapping to the sorted list.
     *
     * @param prefix
     * @param namespaceURI
     */
    public void addNamespace(String prefix, String namespaceURI) {

        this.pfxToUri.put(prefix, namespaceURI);
        this.uriToPfx.put(namespaceURI, prefix);
    }

    /*
     * (non-Javadoc)
     *
     * @see javax.xml.namespace.NamespaceContext#getNamespaceURI(java.lang.String)
     */
    public String getNamespaceURI(String prefix) {

        return this.pfxToUri.get(prefix);
    }

    /*
     * (non-Javadoc)
     *
     * @see javax.xml.namespace.NamespaceContext#getPrefix(java.lang.String)
     */
    public String getPrefix(String namespaceURI) {

        return this.uriToPfx.get(namespaceURI);
    }

    /*
     * (non-Javadoc)
     *
     * @see javax.xml.namespace.NamespaceContext#getPrefixes(java.lang.String)
     */
    public Iterator<String> getPrefixes(String namespaceURI) {

        return this.pfxToUri.keySet().iterator();
    }

}