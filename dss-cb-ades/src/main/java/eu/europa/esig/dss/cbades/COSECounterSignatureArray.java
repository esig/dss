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
import eu.europa.esig.dss.utils.Utils;

import java.util.List;
import java.util.Objects;

/**
 * Represents a [+ COSE_Countersignature] CBOR array structure
 */
public class COSECounterSignatureArray implements COSECounterSignStructure {

    /** The context of the counter signature */
    private COSESignatureType context;

    /** Defines the encoding of the structure */
    private boolean tagged;

    /** The master signature structure */
    private COSEStructure masterSignature;

    /** Collection of embedded COSECounterSignature's */
    private List<COSECounterSignature> coseCounterSignatureList;

    @Override
    public COSESignatureType getContext() {
        return context;
    }

    /**
     * Default constructor
     */
    public COSECounterSignatureArray() {
        // empty
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

    /**
     * Gets a list of COSECounterSignature's embedded within the Array
     *
     * @return a list of {@link COSECounterSignature}s
     */
    public List<COSECounterSignature> getCoseCounterSignatureList() {
        return coseCounterSignatureList;
    }

    /**
     * Sets a list of {@link COSECounterSignature}s
     *
     * @param coseCounterSignatureList a list of {@link COSECounterSignature}s
     */
    public void setCoseCounterSignatureList(List<COSECounterSignature> coseCounterSignatureList) {
        this.coseCounterSignatureList = coseCounterSignatureList;
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
        if (Utils.isCollectionEmpty(coseCounterSignatureList)) {
            throw new IllegalStateException("Collection of COSECounterSignature's cannot be null or empty " +
                    "in COSECounterSignature CBOR Array!");
        }
        final CBORValue.CBORArrayEditor arrayEditor = CBOR.array(coseCounterSignatureList.size());
        for (COSECounterSignature counterSignature : coseCounterSignatureList) {
            arrayEditor.add(counterSignature.toCBORValue());
        }
        CBORValue coseCounterSignatureArray = arrayEditor.value();
        if (tagged) {
            Objects.requireNonNull(getContext(), "Context shall be defined for a tagged CBOR object!");
            coseCounterSignatureArray = CBOR.tag(getContext().getTag(), coseCounterSignatureArray);
        }
        return coseCounterSignatureArray;
    }

}
