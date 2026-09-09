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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Objects;

/**
 * Default implementation of {@link MdocDeviceAuthenticationBuilder}
 */
public class DefaultMdocDeviceAuthenticationBuilder implements MdocDeviceAuthenticationBuilder {

    /**
     * Default constructor
     */
    public DefaultMdocDeviceAuthenticationBuilder() {
        // empty
    }

    @Override
    public DSSDocument build(final MdocKeyBindingParameters keyBindingParameters) {
        ensureKeyBindingParameters(keyBindingParameters);


        try {
            CBORValue deviceAuthentication = CBOR.array()
                    .add(MdocConstants.DEVICE_AUTHENTICATION)
                    .add(CBORUtils.parseCbor(keyBindingParameters.getSessionTranscript()))
                    .add(keyBindingParameters.getDocType())
                    .add(getDeviceNameSpacesBuilder().buildDeviceNameSpacesBytes(keyBindingParameters))
                    .value();

            CBORValue deviceAuthenticationBytes = CBORTags.encodedCbor(deviceAuthentication.encodeToBytes());
            return new InMemoryDocument(CBORUtils.serializeCbor(deviceAuthenticationBytes));

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to build DeviceAuthentication. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * This method verifies the validity the key binding parameters.
     *
     * @param keyBindingParameters {@link MdocKeyBindingParameters}
     */
    protected void ensureKeyBindingParameters(final MdocKeyBindingParameters keyBindingParameters) {
        Objects.requireNonNull(keyBindingParameters, "keyBindingParameters must not be null");
        Objects.requireNonNull(keyBindingParameters.getDocType(), "DocType must not be null");
        Objects.requireNonNull(keyBindingParameters.getSessionTranscript(), "SessionTranscript must not be null");

        if (!CBORUtils.isCbor(keyBindingParameters.getSessionTranscript())) {
            throw new DSSException("Session transcript must be a CBOR object");
        }
    }

    /**
     * Gets the {@link MdocDeviceNameSpacesBuilder}
     *
     * @return {@link MdocDeviceNameSpacesBuilder}
     */
    protected MdocDeviceNameSpacesBuilder getDeviceNameSpacesBuilder(){
        return new DefaultMdocDeviceNameSpacesBuilder();
    }
}
