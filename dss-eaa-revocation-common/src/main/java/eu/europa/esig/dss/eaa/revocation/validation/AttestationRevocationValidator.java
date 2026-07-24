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
package eu.europa.esig.dss.eaa.revocation.validation;

import eu.europa.esig.dss.spi.eaa.Attestation;
import eu.europa.esig.dss.spi.eaa.AttestationRevocationToken;

import java.util.List;

/**
 * This class verifies whether the provided EAA supports the given revocation status verification mechanism,
 * and performs validation on the extracted token document, if applicable.
 *
 */
public interface AttestationRevocationValidator {

    /**
     * Verifies whether the EAA supports the current status verification mechanism.
     * For example EAA contains the required payload claim.
     *
     * @param attestation {@link Attestation} to be verified
     * @return TRUE if the EAA supports given status verification mechanism, FALSE otherwise
     */
    boolean isSupported(Attestation attestation);

    /**
     * Gets a list of URIs to be used for extraction of a token containing information about the EAA revocation
     *
     * @param attestation {@link Attestation} to be verified
     * @return a list of {@link String}s
     */
    List<String> getUris(Attestation attestation);

    /**
     * Validates the {@code eaa} using the {@code statusDocument}
     *
     * @param attestation {@link Attestation} to be verified
     * @param revocationDocument binaries of a token containing information about the EAA revocation data
     * @return {@link AttestationRevocationToken}
     */
    AttestationRevocationToken validate(Attestation attestation, byte[] revocationDocument);

}
