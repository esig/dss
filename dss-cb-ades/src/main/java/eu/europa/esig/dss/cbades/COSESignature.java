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
 * Represents a COSE_Signature object defined in RFC 9052 "4.1. Signing with One or More Signers"
 *
 */
public class COSESignature implements COSEStructure {

    /** The protected attributes of the signer structure */
    private COSEProtectedHeader protectedHeader;

    /** The unprotected attributes of the signer structure */
    private COSEUnprotectedHeader unprotectedHeader;

    /** The computed signature value of the signer */
    private CBORValue signature;

    /** Parent container of the signature, when applicable */
    private COSEStructure parent;

    /**
     * Default constructor to instantiate an empty COSESignature object
     */
    public COSESignature() {
        // empty
    }

    /**
     * Gets a protected attributes header of the signer.
     * Instantiates an empty map, when absent
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
     * Sets a protected attributes header of the signer
     *
     * @param protectedHeader {@link COSEProtectedHeader}
     */
    public void setProtectedHeader(COSEProtectedHeader protectedHeader) {
        this.protectedHeader = protectedHeader;
    }

    /**
     * Gets an unprotected attributes header of the signer.
     * Instantiates an empty map, when absent
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
     * Sets an unprotected attributes header of the signer
     *
     * @param unprotectedHeader {@link COSEUnprotectedHeader}
     */
    public void setUnprotectedHeader(COSEUnprotectedHeader unprotectedHeader) {
        this.unprotectedHeader = unprotectedHeader;
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

    /**
     * Gets parent signature structure, when applicable
     *
     * @return {@link COSEStructure}
     */
    public COSEStructure getParent() {
        return parent;
    }

    /**
     * Sets parent signature structure
     *
     * @param parent {@link COSEStructure}
     */
    public void setParent(COSEStructure parent) {
        this.parent = parent;
    }

    @Override
    public byte[] serialize() {
        CBORValue cborValue = CBOR.array(3)
                .add(protectedHeader.asByteString())
                .add(unprotectedHeader.getValue())
                .add(signature)
                .value();
        return CBORUtils.serializeCbor(cborValue);
    }

    @Override
    public COSESignatureType getContext() {
        return COSESignatureType.COSE_SIGNATURE;
    }

}
