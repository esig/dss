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
package eu.europa.esig.dss.attestation.revocation.validation.statuslist;

/**
 * Loads a relevant implementation for an EAA's Token Status List (TSL) processing
 *
 */
public interface StatusListValidatorFactory {

    /**
     * This method tests if the current implementation of {@link TokenStatusListValidator}
     * supports the given document
     *
     * @param eaaStatusList
     *                 the document to be tested
     * @return true, if the {@link TokenStatusListValidator} supports the given document
     */
    boolean isSupported(byte[] eaaStatusList);

    /**
     * This method instantiates a {@link TokenStatusListValidator} with the given document
     *
     * @param eaaStatusList
     *                 the document to be used for the {@link TokenStatusListValidator}
     *                 creation
     * @return an instance of {@link TokenStatusListValidator} with the document
     */
    TokenStatusListValidator create(byte[] eaaStatusList);

}

