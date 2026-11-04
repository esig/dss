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

import java.util.Objects;

/**
 * Identifies the context of the signature. E.g. a COSE_Sign or COSE_Sign1 signature.
 *
 */
public enum COSESignatureType {

    /** For signatures using the COSE_Signature structure */
    COSE_SIGN("Signature", "COSE_Sign", 98L),

    /** For signatures using the COSE_Sign1 structure */
    COSE_SIGN1("Signature1", "COSE_Sign1", 18L),

    /** For signatures using the COSE_Signature structure */
    COSE_SIGNATURE(null, null, null),

    /** For full counter-signatures */
    COSE_COUNTER_SIGNATURE("CounterSignature", "COSE_Countersignature", 19L, true, false),

    /** For abbreviated counter-signatures0 */
    COSE_COUNTER_SIGNATURE0("CounterSignature0", "COSE_Countersignature0", null, true, false),

    /** For full counter-signatures with other_fields present */
    COSE_COUNTER_SIGNATURE_V2("CounterSignatureV2", "COSE_Countersignature_V2", 19L, true, true),

    /** For abbreviated counter-signatures0 with other_fields present */
    COSE_COUNTER_SIGNATURE0_V2("CounterSignature0V2", "COSE_Countersignature0_V2", null, true, true);

    /** The context label used as a part of a DTBS computation */
    private final String context;

    /** Gets the COSE signature context's label as defined in RFC 8152 / RFC 9052 / RFC 9338 */
    private final String label;

    /** The tag label code of the corresponding structure */
    private final Long tag;

    /** Defines if the signature context corresponds to a counter signature */
    private final boolean counterSignature;

    /** Defines if the signature context corresponds to an RFC 9338 counter signature V2 */
    private final boolean counterSignatureV2;

    /**
     * Default constructor
     *
     * @param context {@link String} context label
     * @param label {@link String} user-friendly label as defined in RFC
     * @param tag long value of the tag label key
     */
    COSESignatureType(final String context, final String label, final Long tag) {
        this(context, label, tag, false, false);
    }

    /**
     * Default constructor
     *
     * @param context {@link String} context label
     * @param label {@link String} user-friendly label as defined in RFC
     * @param tag long value of the tag label key
     * @param counterSignature whether the context corresponds to the counter signature
     * @param counterSignatureV2 whether the context corresponds to the counter signature V2
     */
    COSESignatureType(final String context, final String label, final Long tag, final boolean counterSignature,
                      final boolean counterSignatureV2) {
        this.context = context;
        this.label = label;
        this.tag = tag;
        this.counterSignature = counterSignature;
        this.counterSignatureV2 = counterSignatureV2;
    }

    /**
     * Gets the context text string identifying the context of the signature.
     * The value is used for DTBS computation.
     *
     * @return {@link String}
     */
    public String getContext() {
        return context;
    }

    /**
     * Gets the RFC definition user-friendly label
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets the tag of the corresponding signature structure
     *
     * @return long value of the tag label key
     */
    public long getTag() {
        Objects.requireNonNull(tag, String.format("The tag is not available for COSESignatureType '%s'", this.name()));
        return tag;
    }

    /**
     * Gets if the context corresponds to a counter signature
     *
     * @return TRUE if the context corresponds to a counter signature type
     */
    public boolean isCounterSignature() {
        return counterSignature;
    }

    /**
     * Gets if the context corresponds to an RFC 9338 counter signature V2
     *
     * @return TRUE if the context corresponds to a RFC 9338 counter signature V2 type
     */
    public boolean isCounterSignatureV2() {
        return counterSignatureV2;
    }

    /**
     * Gets the corresponding {@code COSESignatureType} enum for the given {@code label}, if found
     *
     * @param label {@link String}
     * @return {@link COSESignatureType}
     */
    public static COSESignatureType forLabel(final String label) {
        Objects.requireNonNull(label, "Label string shall be defined!");
        for (COSESignatureType coseSignatureType : values()) {
            if (label.equals(coseSignatureType.label)) {
                return coseSignatureType;
            }
        }
        return null;
    }

}
