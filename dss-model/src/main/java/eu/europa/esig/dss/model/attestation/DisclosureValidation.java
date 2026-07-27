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
package eu.europa.esig.dss.model.attestation;

import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;

import java.util.Objects;

/**
 * This class represents a validation result of a selectable disclosure provided
 * with presentation of attestation
 *
 */
public class DisclosureValidation extends ReferenceValidation {

    private static final long serialVersionUID = -191049727174569696L;

    /** Disclosure object, when applicable */
    private SelectivelyDisclosableClaim disclosure;

    /** Namespace of the selective disclosure (mdoc) */
    private String namespace;

    /** Unique identifier of the selective disclosure (mdoc) */
    private Long digestId;

    /**
     * Default constructor
     */
    public DisclosureValidation() {
        // empty
    }

    /**
     * Constructor with a provided disclosure
     *
     * @param disclosure {@link SelectivelyDisclosableClaim}
     */
    public DisclosureValidation(SelectivelyDisclosableClaim disclosure) {
        Objects.requireNonNull(disclosure, "Disclosure cannot be null!");
        this.disclosure = disclosure;
    }

    /**
     * Gets disclosure when applicable
     *
     * @return {@link SelectivelyDisclosableClaim}
     */
    public SelectivelyDisclosableClaim getDisclosure() {
        return disclosure;
    }

    /**
     * Gets the provided disclosure name
     *
     * @return {@link String}
     */
    public String getClaimName() {
        return disclosure != null ? disclosure.getName() : null;
    }

    /**
     * Gets the original provided disclosure claim value
     *
     * @return {@link VerifiedClaim}
     */
    public VerifiedClaim getValue() {
        return disclosure != null ? disclosure.getClaimValue() : null;
    }

    /**
     * Gets disclosure's namespace (mdoc only)
     *
     * @return {@link String}
     */
    public String getNamespace() {
        if (namespace != null) {
            return namespace;
        }
        return disclosure != null ? disclosure.getNamespace() : null;
    }

    /**
     * Sets the namespace of the selective disclosure (mdoc only)
     *
     * @param namespace {@link String}
     */
    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    /**
     * Gets the digest Id (mdoc only)
     *
     * @return {@link Long}
     */
    public Long getDigestId() {
        if (digestId != null) {
            return digestId;
        }
        return disclosure != null ? disclosure.getDigestId() : null;
    }

    /**
     * Sets the unique identifier of the selective disclosure (mdoc only)
     *
     * @param digestId {@link Long}
     */
    public void setDigestId(Long digestId) {
        this.digestId = digestId;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        DisclosureValidation that = (DisclosureValidation) object;
        return Objects.equals(disclosure, that.disclosure)
                && Objects.equals(namespace, that.namespace)
                && Objects.equals(digestId, that.digestId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(disclosure);
        result = 31 * result + Objects.hashCode(namespace);
        result = 31 * result + Objects.hashCode(digestId);
        return result;
    }

}
