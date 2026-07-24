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
import eu.europa.esig.dss.model.attestation.SelectivelyDisclosableClaim;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * This class is used to build an identifier for EAA object
 */
public class AttestationIdentifierBuilder {

    /**
     * Default constructor
     */
    public AttestationIdentifierBuilder() {
        // empty
    }

    /**
     * Builds an {@code EAAIdentifier} for the given {@code attestation}
     *
     * @param eaa {@link AttestationIdentifier} to build identifier for
     * @return {@link AttestationIdentifier}
     */
    public AttestationIdentifier build(DefaultAttestation eaa) {
        return new AttestationIdentifier(buildBinaries(eaa));
    }

    /**
     * Builds unique binary data describing the object
     *
     * @param eaa {@link Attestation} to build binaries for identifier on
     * @return a byte array
     */
    protected byte[] buildBinaries(DefaultAttestation eaa) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            for (AdvancedSignature signature : eaa.getSignatures()) {
                baos.write(signature.getId().getBytes());
            }
            if (Utils.isCollectionNotEmpty(eaa.getDisclosures())) {
                for (SelectivelyDisclosableClaim disclosure : eaa.getDisclosures()) {
                    baos.write(disclosure.getSalt());
                    if (disclosure.getName() != null) {
                        baos.write(disclosure.getName().getBytes());
                    }
                    // claim value is not used to avoid unnecessary information disclosure
                }
            }
            if (eaa.getKeyBindingSignature() != null) {
                baos.write(eaa.getKeyBindingSignature().getId().getBytes());
            }
            return baos.toByteArray();

        } catch (IOException e) {
            throw new DSSException(String.format("An error occurred while building an Identifier : %s", e.getMessage()), e);
        }
    }

}
