/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jades;

/**
 * Contains possible types for a claimed signing time header incorporation within a JAdES signature
 *
 */
public enum JAdESSigningTimeType {

    /**
     * The iat header parameter as specified in IETF RFC 7519, clause 4.1.6.
     * Before 2025-07-15T00:00:00Z, this header parameter should be incorporated in new JAdES signatures
     * instead the sigT header parameter specified in clause 5.2.1 of the present document.
     * Starting at 2025-07-15T00:00:00Z, this header parameter shall be incorporated in new JAdES signatures.
     */
    IAT,

    /**
     * The sigT header parameter as specified in ETSI TS 119 182-1, clause 5.2.1.
     * Before 2025-07-15T00:00:00Z this header parameter should not be incorporated in new JAdES signatures.
     * Instead, the iaT header parameter should be included.
     * Starting at 2025-07-15T00:00:00Z this header parameter shall not be incorporated in new JAdES signatures.
     */
    SIG_T

}
