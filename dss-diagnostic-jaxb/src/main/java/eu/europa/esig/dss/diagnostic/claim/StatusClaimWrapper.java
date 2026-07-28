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
import eu.europa.esig.dss.diagnostic.jaxb.XmlIdentifierListClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStatusClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStatusListClaim;

import java.util.HashMap;
import java.util.Map;

/**
 * Wraps an {@code eu.europa.esig.dss.diagnostic.jaxb.XmlStatusClaim}
 *
 */
public class StatusClaimWrapper extends ClaimWrapper {

    /**
     * Default constructor
     *
     * @param wrapped {@link XmlStatusClaim}
     */
    public StatusClaimWrapper(final XmlStatusClaim wrapped) {
        super(wrapped);
    }

    /**
     * Gets the status list
     *
     * @return {@link StatusListClaimWrapper}
     */
    public StatusListClaimWrapper getStatusList() {
        XmlStatusListClaim statusList = getWrapped().getStatusList();
        if (statusList != null) {
            return new StatusListClaimWrapper(statusList, this);
        }
        return null;
    }

    /**
     * Gets the identifier list
     *
     * @return {@link IdentifierListClaimWrapper}
     */
    public IdentifierListClaimWrapper getIdentifierList() {
        XmlIdentifierListClaim identifierList = getWrapped().getIdentifierList();
        if (identifierList != null) {
            return new IdentifierListClaimWrapper(identifierList, this);
        }
        return null;
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
     * Gets the status list type
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getType() {
        XmlClaim type = getWrapped().getType();
        if (type != null) {
            return new ClaimWrapper(type, this);
        }
        return null;
    }

    /**
     * Gets the status list purpose
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPurpose() {
        XmlClaim purpose = getWrapped().getPurpose();
        if (purpose != null) {
            return new ClaimWrapper(purpose, this);
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
        StatusListClaimWrapper statusList = getStatusList();
        if (statusList != null) {
            result.put(statusList.getName(), statusList);
        }
        IdentifierListClaimWrapper identifierList = getIdentifierList();
        if (identifierList != null) {
            result.put(identifierList.getName(), identifierList);
        }
        ClaimWrapper index = getIndex();
        if (index != null) {
            result.put(index.getName(), index);
        }
        ClaimWrapper uri = getUri();
        if (uri != null) {
            result.put(uri.getName(), uri);
        }
        ClaimWrapper type = getType();
        if (type != null) {
            result.put(type.getName(), type);
        }
        ClaimWrapper purpose = getPurpose();
        if (purpose != null) {
            result.put(purpose.getName(), purpose);
        }
        return result;
    }

    @Override
    public XmlStatusClaim getWrapped() {
        return (XmlStatusClaim) super.getWrapped();
    }

}
