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
package eu.europa.esig.dss.attestation.sd.jwt;

import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTSelectiveDisclosure;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;

import java.io.Serializable;
import java.util.List;

/**
 * This class represents a parsed SD-JWT object
 *
 */
public class SDJWTSerializationObject implements Serializable {

    private static final long serialVersionUID = 2321956568937413822L;

    /** The attestation signature */
    private JWSJsonSerializationObject signature;

    /** List of disclosures attached to the presentation */
    private List<SDJWTSelectiveDisclosure> disclosures;

    /** Key binding signature attached to the presentation */
    private JWSJsonSerializationObject keyBindingSignature;

    /** Defines the JWSSerializationType of the SD-JWT token */
    private JWSSerializationType jwsSerializationType;

    /**
     * Default constructor instantiating object with null values
     */
    public SDJWTSerializationObject() {
        // empty
    }

    /**
     * Gets the JWS signature used to create the attestation
     *
     * @return {@link JWSJsonSerializationObject}
     */
    public JWSJsonSerializationObject getSignature() {
        return signature;
    }

    /**
     * Sets the JWS signature used to create the attestation
     *
     * @param signature {@link JWSJsonSerializationObject}
     */
    public void setSignature(JWSJsonSerializationObject signature) {
        this.signature = signature;
    }

    /**
     * Gets a list of disclosures supplied with the presentation of attestation
     *
     * @return a list of {@link SDJWTSelectiveDisclosure}s
     */
    public List<SDJWTSelectiveDisclosure> getDisclosures() {
        return disclosures;
    }

    /**
     * Sets a list of disclosures supplied with the presentation of attestation
     *
     * @param disclosures a list of {@link SDJWTSelectiveDisclosure}s
     */
    public void setDisclosures(List<SDJWTSelectiveDisclosure> disclosures) {
        this.disclosures = disclosures;
    }

    /**
     * Gets a key binding signature supplied with the presentation of attestation
     *
     * @return {@link JWSJsonSerializationObject}
     */
    public JWSJsonSerializationObject getKeyBindingSignature() {
        return keyBindingSignature;
    }

    /**
     * Sets a key binding signature supplied with the presentation of attestation
     *
     * @param keyBindingSignature {@link JWSJsonSerializationObject}
     */
    public void setKeyBindingSignature(JWSJsonSerializationObject keyBindingSignature) {
        this.keyBindingSignature = keyBindingSignature;
    }

    /**
     * Gets the used {@code JWSSerializationType} for the token
     *
     * @return {@link JWSSerializationType}
     */
    public JWSSerializationType getJWSSerializationType() {
        return jwsSerializationType;
    }

    /**
     * Sets the {@code JWSSerializationType}
     *
     * @param jwsSerializationType {@link JWSSerializationType}
     */
    public void setJWSSerializationType(JWSSerializationType jwsSerializationType) {
        this.jwsSerializationType = jwsSerializationType;
    }

}
