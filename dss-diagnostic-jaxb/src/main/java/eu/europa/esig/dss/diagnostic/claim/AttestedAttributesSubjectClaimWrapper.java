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

import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestedAttributesSubjectClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;

import java.util.HashMap;
import java.util.Map;

/**
 * Wraps an {@code eu.europa.esig.dss.diagnostic.jaxb.XmlAttestedAttributesSubjectClaim}
 *
 */
public class AttestedAttributesSubjectClaimWrapper extends ClaimWrapper {

    /**
     * Default constructor
     *
     * @param wrapped {@link XmlAttestedAttributesSubjectClaim}
     */
    public AttestedAttributesSubjectClaimWrapper(final XmlAttestedAttributesSubjectClaim wrapped) {
        super(wrapped);
    }

    /**
     * Gets the revocation's unique index identifier
     *
     * @return {@link ClaimWrapper}
     */
    public AttestedAttributesSubjectClaimIdWrapper getSubjectId() {
        XmlClaim subjectId = getWrapped().getSubjectId();
        if (subjectId != null) {
            return new AttestedAttributesSubjectClaimIdWrapper(subjectId, this);
        }
        return null;
    }

    /**
     * Gets the revocation's unique index identifier
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getSubjectPseudonym() {
        XmlClaim pseudonym = getWrapped().getSubjectPseudonym();
        if (pseudonym != null) {
            return new ClaimWrapper(pseudonym, this);
        }
        return null;
    }

    /**
     * Gets the revocation's unique index identifier
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAttributes() {
        XmlClaim attributes = getWrapped().getAttributes();
        if (attributes != null) {
            return new ClaimWrapper(attributes, this);
        }
        return null;
    }

    @Override
    public Map<String, ClaimWrapper> getMap() {
        final Map<String, ClaimWrapper> result = new HashMap<>(super.getMap());
        ClaimWrapper subjectId = getSubjectId();
        if (subjectId != null) {
            result.put(subjectId.getName(), subjectId);
        }
        ClaimWrapper subjectPseudonym = getSubjectPseudonym();
        if (subjectPseudonym != null) {
            result.put(subjectPseudonym.getName(), subjectPseudonym);
        }
        ClaimWrapper attributes = getAttributes();
        if (attributes != null) {
            result.put(attributes.getName(), attributes);
        }
        return result;
    }

    @Override
    public XmlAttestedAttributesSubjectClaim getWrapped() {
        return (XmlAttestedAttributesSubjectClaim) super.getWrapped();
    }

}
