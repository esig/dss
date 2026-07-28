/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.diagnostic.claim;

import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStatusListClaim;

import java.util.HashMap;
import java.util.Map;

/**
 * Wraps an {@code eu.europa.esig.dss.diagnostic.jaxb.XmlStatusListClaim}
 *
 */
public class StatusListClaimWrapper extends ClaimWrapper {

    /**
     * Default constructor
     *
     * @param wrapped {@link XmlStatusListClaim}
     */
    public StatusListClaimWrapper(final XmlStatusListClaim wrapped) {
        super(wrapped);
    }

    /**
     * Constructor with a parent provided
     *
     * @param wrapped {@link XmlStatusListClaim}
     * @param parent {@link ClaimWrapper}
     */
    public StatusListClaimWrapper(final XmlStatusListClaim wrapped, final ClaimWrapper parent) {
        super(wrapped, parent);
    }

    /**
     * Gets the token's unique index identifier
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getIndex() {
        XmlClaim index = getWrapped().getIndex();
        if (index != null) {
            return new ClaimWrapper(index, this);
        }
        return null;
    }

    /**
     * Gets the status list uri
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getUri() {
        XmlClaim uri = getWrapped().getUri();
        if (uri != null) {
            return new ClaimWrapper(uri, this);
        }
        return null;
    }

    /**
     * Gets the certificate containing the public key that signed or sealed the top-level
     * certificate in the x5chain element in the MSO revocation list structure
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getCertificate() {
        XmlClaim certificate = getWrapped().getCertificate();
        if (certificate != null) {
            return new ClaimWrapper(certificate, this);
        }
        return null;
    }

    @Override
    public boolean isMap() {
        return true;
    }

    @Override
    public Map<String, ClaimWrapper> getMap() {
        final Map<String, ClaimWrapper> result = new HashMap<>(super.getMap());
        ClaimWrapper index = getIndex();
        if (index != null) {
            result.put(index.getName(), index);
        }
        ClaimWrapper uri = getUri();
        if (uri != null) {
            result.put(uri.getName(), uri);
        }
        ClaimWrapper certificate = getCertificate();
        if (certificate != null) {
            result.put(certificate.getName(), certificate);
        }
        return result;
    }

    @Override
    public XmlStatusListClaim getWrapped() {
        return (XmlStatusListClaim) super.getWrapped();
    }

}
