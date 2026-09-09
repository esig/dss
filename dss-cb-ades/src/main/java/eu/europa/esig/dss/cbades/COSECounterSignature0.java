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
package eu.europa.esig.dss.cbades;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.enumerations.COSESignatureType;

/**
 * This class represents an RFC 9338 Abbreviated COSE_Countersignature0 structure
 *
 */
public class COSECounterSignature0 implements COSECounterSignStructure  {

    /** The context of the counter signature */
    private COSESignatureType context;

    /** Defines the encoding of the structure */
    private boolean tagged;

    /** The computed signature value of the signer */
    private CBORValue signature;

    /** The master signature structure */
    private COSEStructure masterSignature;

    /**
     * Instantiates an empty COSE_Countersignature0 structure object
     */
    public COSECounterSignature0() {
        // empty
    }

    @Override
    public COSESignatureType getContext() {
        return context;
    }

    /**
     * Sets the context of the COSE counter signature
     *
     * @param context {@link COSESignatureType}
     */
    public void setContext(COSESignatureType context) {
        this.context = context;
    }

    @Override
    public boolean isTagged() {
        return tagged;
    }

    /**
     * Sets whether the signature structure is encoded as tagged or untagged
     *
     * @param tagged whether the signature structure is encoded as tagged or untagged
     */
    public void setTagged(boolean tagged) {
        this.tagged = tagged;
    }

    /**
     * Sets a signature value of the signer
     *
     * @return {@link CBORValue}
     */
    public CBORValue getSignature() {
        return signature;
    }

    /**
     * Sets the signature value of the signer
     *
     * @param signature {@link CBORByteString}
     * @deprecated since DSS 6.6. Use {@link #setSignature(CBORValue)}.
     */
    @Deprecated
    public void setSignature(CBORByteString signature) {
        this.signature = CBOR.bytes(signature.getValueAsBytes());
    }

    /**
     * Sets the signature value of the signer
     *
     * @param signature {@link CBORValue}
     */
    public void setSignature(CBORValue signature) {
        this.signature = signature;
    }

    @Override
    public COSEStructure getMasterSignature() {
        return masterSignature;
    }

    /**
     * Sets the master signature structure
     *
     * @param masterSignature {@link COSEStructure}
     */
    public void setMasterSignature(COSEStructure masterSignature) {
        this.masterSignature = masterSignature;
    }

    @Override
    public byte[] serialize() {
        CBORValue cborArray = toCBORValue();
        return CBORUtils.serializeCbor(cborArray);
    }

    @Override
    @Deprecated
    public CBORByteString toCBORObject() {
        return new CBORByteString(getSignature().asBytes());
    }

    @Override
    public CBORValue toCBORValue() {
        return getSignature();
    }

}
