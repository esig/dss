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

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORNull;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.enumerations.COSESignatureType;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a COSESign (RFC 9052 "4.1. Signing with One or More Signers") signature structure,
 * allowing signing with one or multiple signers
 *
 */
public class COSESign implements COSESignStructure {

    /** Defines the encoding of the structure */
    private boolean tagged;

    /** Protected attributes of the body structure */
    private COSEProtectedHeader protectedHeader;

    /** Unprotected attributes of the body structure */
    private COSEUnprotectedHeader unprotectedHeader;

    /** Payload to be signed, when present */
    private CBORObject payload;

    /** List of signers */
    private List<COSESignature> signatures;

    /**
     * Instantiates an empty COSE_Sign structure object
     */
    public COSESign() {
        // empty
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
     * Gets a protected attributes header of the body structure.
     * Instantiates an empty map when omitted.
     *
     * @return {@link COSEProtectedHeader}
     */
    public COSEProtectedHeader getProtectedHeader() {
        if (protectedHeader == null) {
            protectedHeader = new COSEProtectedHeader();
        }
        return protectedHeader;
    }

    /**
     * Sets a protected attributes header of the body structure.
     *
     * @param protectedHeader {@link COSEProtectedHeader}
     */
    public void setProtectedHeader(COSEProtectedHeader protectedHeader) {
        this.protectedHeader = protectedHeader;
    }

    /**
     * Gets an unprotected attributes header of the body structure.
     * Instantiates an empty map when omitted.
     *
     * @return {@link COSEUnprotectedHeader}
     */
    public COSEUnprotectedHeader getUnprotectedHeader() {
        if (unprotectedHeader == null) {
            unprotectedHeader = new COSEUnprotectedHeader();
        }
        return unprotectedHeader;
    }

    /**
     * Sets an unprotected attributes header of the body structure.
     *
     * @param unprotectedHeader {@link COSEUnprotectedHeader}
     */
    public void setUnprotectedHeader(COSEUnprotectedHeader unprotectedHeader) {
        this.unprotectedHeader = unprotectedHeader;
    }

    @Override
    public CBORObject getPayload() {
        if (payload == null) {
            payload = new CBORNull();
        }
        return payload;
    }

    /**
     * Sets a content to be signed.
     *
     * @param payload {@link CBORObject}
     */
    public void setPayload(CBORObject payload) {
        this.payload = payload;
    }

    /**
     * Gets a list of signers.
     * Instantiates an empty list, when value is absent.
     *
     * @return a list of {@link COSESignature}s
     */
    public List<COSESignature> getSignatures() {
        if (signatures == null) {
            signatures = new ArrayList<>();
        }
        return signatures;
    }

    /**
     * Sets a list of signers.
     *
     * @param signatures a list of {@link COSESignature}s
     */
    public void setSignatures(List<COSESignature> signatures) {
        this.signatures = new ArrayList<>(signatures);
    }

    @Override
    public byte[] serialize() {
        final CBORArray coseSign = new CBORArray(4);
        if (tagged) {
            coseSign.setTag(getContext().getTag());
        }
        coseSign.add(getProtectedHeader().getByteString());
        coseSign.add(getUnprotectedHeader());
        coseSign.add(getPayload());

        List<COSESignature> signaturesList = getSignatures();
        CBORArray coseSignaturesArray = new CBORArray(signaturesList.size());
        for (COSESignature coseSignature : signaturesList) {
            CBORArray coseSignatureArray = new CBORArray(3);
            coseSignatureArray.add(coseSignature.getProtectedHeader().getByteString());
            coseSignatureArray.add(coseSignature.getUnprotectedHeader());
            coseSignatureArray.add(coseSignature.getSignature());
            coseSignaturesArray.add(coseSignatureArray);
        }
        coseSign.add(coseSignaturesArray.toCBORValue());
        return CBORUtils.serializeCborObject(coseSign);
    }

    @Override
    public COSESignatureType getContext() {
        return COSESignatureType.COSE_SIGN;
    }

}
