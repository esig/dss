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
package eu.europa.esig.dss.attestation.mdoc;

/**
 * Contains a list of header names as defined in "6 Implementation of attestation based on ISO/IEC-mdoc" of ETSI TS 119 472-1.
 *
 */
public final class ETSI194721Headers {

    /**
     * Singleton
     */
    private ETSI194721Headers() {
        // empty
    }

    /** An explicit signal identifying the category of the attestation in the context where the attestation has been issued */
    public static final String CATEGORY = "category";

    /** A registration identifier */
    public static final String ISSUING_REGISTRATION_IDENTIFIER = "iss_reg_id";

    /** Contains the pseudonym of the attestation */
    public static final String ALSO_KNOWN_AS = "also_known_as";

    /** Indicates that the attestation shall be used only once, and that it shall not be retained for future use */
    public static final String ONE_TIME = "oneTime";

    /** Indicates  that the validity period of the attestation is so short that it shall not be necessary to check its revocation status */
    public static final String SHORT_LIVED = "shortLived";

    /** Associates one attribute to one entity different than the attestation subject */
    public static final String SUB_ATTRS = "SubAttr";

    /** The subject attribute identifier */
    public static final String SUB_ATTRS_ID = "subId";

    /** The subject attribute pseudonym */
    public static final String SUB_ATTRS_AKA = "subAka";

    /** The family name of the attribute subject */
    public static final String SUB_ATTRS_ID_FAMILY_NAME = "family_name";

    /** The given name of the attribute subject */
    public static final String SUB_ATTRS_ID_GIVEN_NAME = "given_name";

    /** The number of the personal identification data assigned to the attribute subject  */
    public static final String SUB_ATTRS_ID_DOCUMENT_NUMBER = "document_number";

}
