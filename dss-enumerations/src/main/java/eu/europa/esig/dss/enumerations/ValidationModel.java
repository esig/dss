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
package eu.europa.esig.dss.enumerations;

/**
 * Represents a validation model of a certificate chain (e.g. SHELL, CHAIN, etc.)
 *
 */
public enum ValidationModel {

    /**
     * Model for validation of X.509 certificate chains where all certificates have to be valid at a given time
     */
    SHELL,

    /**
     * Model for validation of X.509 certificate chains where all CA certificates have to be valid at the time they
     * were used for issuing a certificate and the end-entity certificate was valid when creating the signature
     */
    CHAIN,

    /**
     * Hybrid validation model, evaluating the signing-certificate at the validation time,
     * while all other intermediate CA certificates at the time of the signing-certificate's issuance
     */
    HYBRID

}
