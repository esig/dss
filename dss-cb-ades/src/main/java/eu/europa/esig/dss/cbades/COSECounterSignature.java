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
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.enumerations.COSESignatureType;

import java.util.Objects;

/**
 * This class represents an RFC 9338 Full COSE_Countersignature structure (Tag '19')
 *
 */
public class COSECounterSignature extends COSESignature implements COSECounterSignStructure {

    /** The context of the counter signature */
    private COSESignatureType context;

    /** Defines the encoding of the structure */
    private boolean tagged;

    /** The master signature structure */
    private COSEStructure masterSignature;

    /**
     * Instantiates an empty COSE_Countersignature structure object
     */
    public COSECounterSignature() {
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
    public CBORArray toCBORObject() {
        return new CBORArray(toCBORValue());
    }

    @Override
    public CBORValue toCBORValue() {
        CBORValue coseCounterSignature = CBOR.array(3)
                .add(getProtectedHeader().asByteString())
                .add(getUnprotectedHeader().getValue())
                .add(getSignature())
                .value();
        if (tagged) {
            Objects.requireNonNull(getContext(), "Context shall be defined for a tagged CBOR object!");
            coseCounterSignature = CBOR.tag(getContext().getTag(), coseCounterSignature);
        }
        return coseCounterSignature;
    }

}
