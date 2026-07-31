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
package eu.europa.esig.dss.attestation.common.validation.identifier;

import eu.europa.esig.dss.attestation.common.validation.DefaultAttestation;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * This class is used to build an identifier for attestation object
 */
public class AttestationIdentifierBuilder {

    /**
     * Default constructor
     */
    public AttestationIdentifierBuilder() {
        // empty
    }

    /**
     * Builds an {@code attestationIdentifier} for the given {@code attestation}
     *
     * @param attestation {@link AttestationIdentifier} to build identifier for
     * @return {@link AttestationIdentifier}
     */
    public AttestationIdentifier build(DefaultAttestation attestation) {
        return new AttestationIdentifier(buildBinaries(attestation));
    }

    /**
     * Builds unique binary data describing the object
     *
     * @param attestation {@link Attestation} to build binaries for identifier on
     * @return a byte array
     */
    protected byte[] buildBinaries(DefaultAttestation attestation) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            for (AdvancedSignature signature : attestation.getSignatures()) {
                baos.write(signature.getId().getBytes());
            }
            if (Utils.isCollectionNotEmpty(attestation.getDisclosures())) {
                for (SelectiveDisclosure disclosure : attestation.getDisclosures()) {
                    baos.write(disclosure.getSalt());
                    if (disclosure.getName() != null) {
                        baos.write(disclosure.getName().getBytes());
                    }
                    // claim value is not used to avoid unnecessary information disclosure
                }
            }
            if (attestation.getKeyBindingSignature() != null) {
                baos.write(attestation.getKeyBindingSignature().getId().getBytes());
            }
            return baos.toByteArray();

        } catch (IOException e) {
            throw new DSSException(String.format("An error occurred while building an Identifier : %s", e.getMessage()), e);
        }
    }

}
