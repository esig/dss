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
package eu.europa.ec.markt.dss;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;

/**
 * A class for namespace context management. It is used by XPath queries.
 */
public final class NamespaceContextMap implements NamespaceContext {

    private final Map<String, String> prefixMap;
    private final Map<String, Set<String>> namespaceMap;

    /**
     * This constructor takes a map of prefixes and their associated namespace URI values. A copy of this map is made and an inverse map is
     * created.
     *
     * @param prefixMap a map of prefix/namespace URI values
     */
    public NamespaceContextMap(final Map<String, String> prefixMap) {

        this.prefixMap = Collections.unmodifiableMap(prefixMap);
        namespaceMap = createNamespaceMap(this.prefixMap);
    }

    private Map<String, Set<String>> createNamespaceMap(Map<String, String> prefixMap) {

        Map<String, Set<String>> nsMap = new HashMap<String, Set<String>>();
        for (Map.Entry<String, String> entry : prefixMap.entrySet()) {

            String nsURI = entry.getValue();
            Set<String> prefixes = nsMap.get(nsURI);
            if (prefixes == null) {

                prefixes = new HashSet<String>();
                nsMap.put(nsURI, prefixes);
            }
            prefixes.add(entry.getKey());
        }
        for (Map.Entry<String, Set<String>> entry : nsMap.entrySet()) {

            Set<String> readOnly = Collections.unmodifiableSet(entry.getValue());
            entry.setValue(readOnly);
        }
        return nsMap;
    }

    @Override
    public String getNamespaceURI(String prefix) {

        checkNotNull(prefix);
        String nsURI = prefixMap.get(prefix);
        return nsURI == null ? XMLConstants.NULL_NS_URI : nsURI;
    }

    @Override
    public String getPrefix(String namespaceURI) {

        checkNotNull(namespaceURI);
        Set<String> set = namespaceMap.get(namespaceURI);
        return set == null ? null : set.iterator().next();
    }

    @Override
    public Iterator<String> getPrefixes(String namespaceURI) {

        checkNotNull(namespaceURI);
        Set<String> set = namespaceMap.get(namespaceURI);
        return set.iterator();
    }

    private void checkNotNull(String value) {

        if (value == null) {
            throw new IllegalArgumentException("null");
        }
    }
}
