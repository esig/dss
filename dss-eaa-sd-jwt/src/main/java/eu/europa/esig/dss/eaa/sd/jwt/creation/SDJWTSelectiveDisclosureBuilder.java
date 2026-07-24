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
package eu.europa.esig.dss.eaa.sd.jwt.creation;

/**
 * Builds a disclosure String to be used on a selectively disclosable claim digest computation and/or Attestation Presentation
 *
 */
public interface SDJWTSelectiveDisclosureBuilder {

    /**
     * Builds a String for a selectively disclosable EAA claim to be used for Digest computation
     *
     * @param name {@link String} element name of the claim
     * @param value {@link Object} value of the claim
     * @param salt {@link String} high entropy data used to reduce hash collision
     * @return {@link SDJWTSelectiveDisclosure}
     */
    SDJWTSelectiveDisclosure build(String name, Object value, String salt);

}
