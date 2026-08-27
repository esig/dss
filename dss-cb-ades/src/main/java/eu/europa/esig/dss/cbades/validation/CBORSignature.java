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
package eu.europa.esig.dss.cbades.validation;

import co.nstant.in.cbor.model.UnicodeString;
import eu.europa.esig.dss.cbades.COSECounterSignStructure;
import eu.europa.esig.dss.cbades.COSECounterSignature;
import eu.europa.esig.dss.cbades.COSECounterSignature0;
import eu.europa.esig.dss.cbades.COSECounterSignatureArray;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSESign;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.COSESignature;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.cbades.COSEStructure;
import eu.europa.esig.dss.cbades.COSEUnprotectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a single COSE signature.
 * The class is used for verification of a cryptographic validity of the COSE signature.
 *
 */
public class CBORSignature {

    private static final Logger LOG = LoggerFactory.getLogger(CBORSignature.class);

    /** Context of the signature */
    private COSESignatureType context;

    /** Defines whether the signature container is tagged */
    private boolean tagged;

    /** Protected attributes of the body structure */
    private COSEProtectedHeader bodyProtectedHeader;

    /** Protected attributes of the signer structure (absent for COSE_Sign1) */
    private COSEProtectedHeader signerProtectedHeader;

    /** Unprotected attributes of the body structure */
    private COSEUnprotectedHeader bodyUnprotectedHeader;

    /** Unprotected attributes of the signer structure (absent for COSE_Sign1) */
    private COSEUnprotectedHeader signerUnprotectedHeader;

    /** Externally supplied data used as a part of a signed data */
    private CBORByteString externallySuppliedData;

    /** The payload to be signed */
    private CBORObject payload;

    /** The payload to be signed */
    private CBORObject otherFields;

    /** The signer's signature value */
    private CBORByteString signature;

    /** Original COSE signature container structure */
    private COSEStructure coseSignStructure;

    /** The original signer signature (applicable only for COSE_Sign) */
    private COSEStructure signerSignature;

    /** The signer's key */
    private Key key;

    /** Cached instance of the signature algorithm defined within 'alg' signed header parameter */
    private SignatureAlgorithm signatureAlgorithm;

    static {
        Security.addProvider(DSSSecurityProvider.getSecurityProvider());
    }

    /**
     * Default constructor to instantiate an empty object
     */
    protected CBORSignature() {
        // empty
    }

    /**
     * This method creates a list of {@code CBORSignature}s for the given {@code COSESignStructure},
     * representing a validation object for each embedded signer.
     *
     * @param coseSignStructure {@link COSESignStructure}
     * @return a list of {@link CBORSignature}
     */
    public static List<CBORSignature> fromCOSESignStructure(COSESignStructure coseSignStructure) {
        Objects.requireNonNull(coseSignStructure, "COSESignStructure cannot be null!");

        if (coseSignStructure instanceof COSESign) {
            return fromCOSESign((COSESign) coseSignStructure);
        } else if (coseSignStructure instanceof COSESign1) {
            return Collections.singletonList(fromCOSESign1((COSESign1) coseSignStructure));
        }
        throw new UnsupportedOperationException(String.format("Unsupported class '%s'", coseSignStructure.getClass()));
    }

    /**
     * This method creates a list of {@code CBORSignature}s for the given {@code COSESign},
     * representing a validation object for each embedded signer.
     *
     * @param coseSign {@link COSESign}
     * @return a list of {@link CBORSignature}
     */
    public static List<CBORSignature> fromCOSESign(COSESign coseSign) {
        Objects.requireNonNull(coseSign, "COSESign cannot be null!");
        Objects.requireNonNull(coseSign.getContext(), "COSE signature context shall be defined!");

        final List<CBORSignature> cborSignatures = new ArrayList<>();
        for (COSESignature coseSignature : coseSign.getSignatures()) {
            final CBORSignature cborSignature = new CBORSignature();
            cborSignature.context = coseSign.getContext();
            cborSignature.tagged = coseSign.isTagged();
            cborSignature.bodyProtectedHeader = coseSign.getProtectedHeader();
            cborSignature.bodyUnprotectedHeader = coseSign.getUnprotectedHeader();
            cborSignature.signerProtectedHeader = coseSignature.getProtectedHeader();
            cborSignature.signerUnprotectedHeader = coseSignature.getUnprotectedHeader();
            cborSignature.payload = coseSign.getPayload();
            cborSignature.signature = coseSignature.getSignature();
            cborSignature.coseSignStructure = coseSign;
            cborSignature.signerSignature = coseSignature;
            cborSignatures.add(cborSignature);
        }
        return cborSignatures;
    }

    /**
     * This method creates a {@code CBORSignature} for the given {@code COSESign1},
     * representing a validation object for the signer.
     *
     * @param coseSign1 {@link COSESign1}
     * @return {@link CBORSignature}
     */
    public static CBORSignature fromCOSESign1(COSESign1 coseSign1) {
        Objects.requireNonNull(coseSign1, "COSESign1 cannot be null!");
        Objects.requireNonNull(coseSign1.getContext(), "COSE signature context shall be defined!");

        final CBORSignature cborSignature = new CBORSignature();
        cborSignature.context = coseSign1.getContext();
        cborSignature.tagged = coseSign1.isTagged();
        cborSignature.bodyProtectedHeader = coseSign1.getProtectedHeader();
        cborSignature.bodyUnprotectedHeader = coseSign1.getUnprotectedHeader();
        cborSignature.payload = coseSign1.getPayload();
        cborSignature.signature = coseSign1.getSignature();
        cborSignature.coseSignStructure = coseSign1;
        return cborSignature;
    }

    /**
     * This method creates a list of {@code CBORSignature}s for the given {@code COSECounterSignStructure},
     * representing a validation object for each embedded signer.
     *
     * @param coseCounterSignStructure {@link COSECounterSignStructure}
     * @return a list of {@link CBORSignature}
     */
    public static List<CBORSignature> fromCOSECounterSignStructure(COSECounterSignStructure coseCounterSignStructure) {
        Objects.requireNonNull(coseCounterSignStructure, "COSECounterSignStructure cannot be null!");

        if (coseCounterSignStructure instanceof COSECounterSignature) {
            return Collections.singletonList(fromCOSECounterSignature((COSECounterSignature) coseCounterSignStructure));
        } else if (coseCounterSignStructure instanceof COSECounterSignatureArray) {
            return fromCOSECounterSignatureArray((COSECounterSignatureArray) coseCounterSignStructure);
        } else if (coseCounterSignStructure instanceof COSECounterSignature0) {
            return Collections.singletonList(fromCOSECounterSignature0((COSECounterSignature0) coseCounterSignStructure));
        }
        throw new UnsupportedOperationException(String.format("Unsupported class '%s'", coseCounterSignStructure.getClass()));
    }

    /**
     * This method creates a {@code CBORSignature} for the given {@code COSECounterSignature},
     * representing a validation object for the signer.
     *
     * @param coseCounterSignature {@link COSECounterSignature}
     * @return {@link CBORSignature}
     */
    public static CBORSignature fromCOSECounterSignature(COSECounterSignature coseCounterSignature) {
        Objects.requireNonNull(coseCounterSignature, "COSECounterSignature cannot be null!");
        Objects.requireNonNull(coseCounterSignature.getContext(), "COSE signature context shall be defined!");
        Objects.requireNonNull(coseCounterSignature.getMasterSignature(), "Master signature shall be defined for a counter signature!");

        final CBORSignature cborSignature = new CBORSignature();
        cborSignature.context = coseCounterSignature.getContext();
        cborSignature.tagged = coseCounterSignature.isTagged();
        cborSignature.signerProtectedHeader = coseCounterSignature.getProtectedHeader();
        cborSignature.signerUnprotectedHeader = coseCounterSignature.getUnprotectedHeader();
        cborSignature.signature = coseCounterSignature.getSignature();
        cborSignature.signerSignature = coseCounterSignature;
        appendBodyStructure(cborSignature, coseCounterSignature);

        return cborSignature;
    }

    private static void appendBodyStructure(CBORSignature cborSignature, COSECounterSignStructure coseCounterSignStructure) {
        COSEStructure masterSignature = coseCounterSignStructure.getMasterSignature();
        switch (masterSignature.getContext()) {
            case COSE_SIGN:
                COSESign coseSign = (COSESign) masterSignature;
                cborSignature.bodyProtectedHeader = coseSign.getProtectedHeader();
                cborSignature.payload = coseSign.getPayload();
                break;

            case COSE_SIGN1:
                COSESign1 coseSign1 = (COSESign1) masterSignature;
                cborSignature.bodyProtectedHeader = coseSign1.getProtectedHeader();
                cborSignature.payload = coseSign1.getPayload();
                if (coseCounterSignStructure.getContext().isCounterSignatureV2()) {
                    /*
                     * RFC 9338
                     *
                     * other_fields: Omitted if there are only two bstr fields in the
                     * target structure. This field is an array of all bstr fields after
                     * the second. As an example, this would be an array of one element
                     * for the COSE_Sign1 structure containing the signature value.
                     *
                     * NOTE: applied only for counter signature(0)V2
                     */
                    cborSignature.otherFields = new CBORArray(Collections.singletonList(coseSign1.getSignature()));
                }
                break;

            case COSE_SIGNATURE:
            case COSE_COUNTER_SIGNATURE:
            case COSE_COUNTER_SIGNATURE_V2:
                COSESignature coseSignature = (COSESignature) masterSignature;
                cborSignature.bodyProtectedHeader = coseSignature.getProtectedHeader();
                cborSignature.payload = coseSignature.getSignature();
                break;

            default:
                // NOTE: countersignature0 may not have other counter signatures
                throw new UnsupportedOperationException(String.format(
                        "The type of master signature '%s' is not supported!", masterSignature.getContext()));
        }
    }

    /**
     * This method creates a list of {@code CBORSignature}s for the given {@code COSECounterSignatureArray},
     * representing a validation object for the signer.
     *
     * @param coseCounterSignatureArray {@link COSECounterSignatureArray}
     * @return a list of {@link CBORSignature}s
     */
    public static List<CBORSignature> fromCOSECounterSignatureArray(COSECounterSignatureArray coseCounterSignatureArray) {
        Objects.requireNonNull(coseCounterSignatureArray, "COSECounterSignature cannot be null!");
        Objects.requireNonNull(coseCounterSignatureArray.getContext(), "COSE signature context shall be defined!");
        if (Utils.isCollectionEmpty(coseCounterSignatureArray.getCoseCounterSignatureList())) {
            throw new IllegalInputException("COSECounterSignature array cannot be empty!");
        }
        final List<CBORSignature> result = new ArrayList<>();
        for (COSECounterSignature counterSignature : coseCounterSignatureArray.getCoseCounterSignatureList()) {
            CBORSignature coseCounterSignature = fromCOSECounterSignature(counterSignature);
            coseCounterSignature.setCoseSignStructure(coseCounterSignatureArray);
            result.add(coseCounterSignature);
        }
        return result;
    }

    /**
     * This method creates a {@code CBORSignature} for the given {@code COSECounterSignature0},
     * representing a validation object for the signer.
     *
     * @param coseCounterSignature0 {@link COSECounterSignature0}
     * @return {@link CBORSignature}
     */
    public static CBORSignature fromCOSECounterSignature0(COSECounterSignature0 coseCounterSignature0) {
        Objects.requireNonNull(coseCounterSignature0, "COSECounterSignature0 cannot be null!");
        Objects.requireNonNull(coseCounterSignature0.getContext(), "COSE signature context shall be defined!");
        Objects.requireNonNull(coseCounterSignature0.getMasterSignature(), "Master signature shall be defined for a counter signature!");

        final CBORSignature cborSignature = new CBORSignature();
        cborSignature.context = coseCounterSignature0.getContext();
        cborSignature.tagged = coseCounterSignature0.isTagged();
        cborSignature.signature = coseCounterSignature0.getSignature();
        cborSignature.signerSignature = coseCounterSignature0;
        appendBodyStructure(cborSignature, coseCounterSignature0);

        return cborSignature;
    }

    /**
     * Returns context of the COSE signature
     *
     * @return {@link COSESignatureType}
     */
    public COSESignatureType getContext() {
        return context;
    }

    /**
     * Gets whether the container of the signature is tagged
     *
     * @return TRUE if the COSE signature container is tagged, FALSE otherwise
     */
    public boolean isTagged() {
        return tagged;
    }

    /**
     * Gets the body protected header
     *
     * @return {@link COSEProtectedHeader}
     */
    public COSEProtectedHeader getBodyProtectedHeader() {
        return bodyProtectedHeader;
    }

    /**
     * Gets the signer protected header.
     * NOTE: the field is present only within COSE_Sign signature structure.
     *
     * @return {@link COSEProtectedHeader}
     */
    public COSEProtectedHeader getSignerProtectedHeader() {
        return signerProtectedHeader;
    }

    /**
     * Gets the body unprotected header
     *
     * @return {@link COSEUnprotectedHeader}
     */
    public COSEUnprotectedHeader getBodyUnprotectedHeader() {
        return bodyUnprotectedHeader;
    }

    /**
     * Gets the signer unprotected header.
     * NOTE: the field is present only within COSE_Sign signature structure.
     *
     * @return {@link COSEUnprotectedHeader}
     */
    public COSEUnprotectedHeader getSignerUnprotectedHeader() {
        return signerUnprotectedHeader;
    }

    /**
     * Gets current CBOR representation of signature binaries
     *
     * @return {@link CBORByteString}
     */
    public CBORByteString getSignature() {
        return signature;
    }

    /**
     * Returns signature value
     *
     * @return byte array containing the signature bytes
     */
    public byte[] getSignatureValue() {
        Objects.requireNonNull(signature, "Signature bytes shall be set.");
        return signature.getValueAsBytes();
    }

    /**
     * Gets externally supplied data
     *
     * @return {@link CBORByteString}
     */
    public CBORByteString getExternallySuppliedData() {
        return externallySuppliedData;
    }

    /**
     * This method sets externally supplied data binaries, when applicable
     *
     * @param externallySuppliedData {@link CBORByteString} representing an externally supplied data
     */
    public void setExternalAttributes(CBORByteString externallySuppliedData) {
        this.externallySuppliedData = externallySuppliedData;
    }

    /**
     * This method sets externally supplied data binaries, when applicable
     *
     * @param externallySuppliedData byte array representing an externally supplied data
     */
    public void setExternalAttributesBytes(byte[] externallySuppliedData) {
        setExternalAttributes(new CBORByteString(externallySuppliedData));
    }

    /**
     * Gets the payload
     *
     * @return {@link CBORObject}
     */
    public CBORObject getPayload() {
        return payload;
    }

    /**
     * Sets the payload
     *
     * @param payload {@link CBORObject}
     */
    public void setPayload(CBORObject payload) {
        this.payload = payload;
    }

    /**
     * Gets the payload bytes, when present
     *
     * @return byte array representing the payload bytes
     */
    public byte[] getPayloadBytes() {
        if (payload != null && payload.isByteString()) {
            return payload.getValueAsBytes();
        }
        return null;
    }

    /**
     * This method allows supplying of a payload
     *
     * @param payload binaries of a payload
     */
    public void setPayloadBytes(byte[] payload) {
        this.payload = new CBORByteString(payload);
    }

    /**
     * Gets other_fields, when present (master signature's payload).
     * NOTE: Applicable for CounterSignatureV2
     *
     * @return {@link CBORObject}
     */
    public CBORObject getOtherFields() {
        return otherFields;
    }

    /**
     * Gets other_fields bytes, when present (master signature's payload)
     *
     * @return byte array representing the first entry of the other_fields array
     */
    public byte[] getOtherFieldsBytes() {
        if (otherFields != null) {
            if (otherFields.isArray()) {
                CBORArray cborArray = (CBORArray) otherFields;
                if (!cborArray.isEmpty()) {
                    CBORObject masterSignatureValue = cborArray.getItem(0);
                    if (masterSignatureValue.isByteString()) {
                        return ((CBORByteString) masterSignatureValue).getValueAsBytes();
                    } else {
                        LOG.warn("Content of the other_fields entry shall be of CBOR Byte String type!");
                    }
                } else {
                    LOG.warn("other_fields array cannot be empty!");
                }
            } else {
                LOG.warn("other_fields shall be of type CBOR Array!");
            }
        }
        return null;
    }

    /**
     * Gets the original COSE signature structure
     *
     * @return {@link COSEStructure}
     */
    public COSEStructure getCoseSignStructure() {
        return coseSignStructure;
    }

    /**
     * Sets the original COSE signature structure
     *
     * @param coseSignStructure {@link COSEStructure}
     */
    public void setCoseSignStructure(COSEStructure coseSignStructure) {
        this.coseSignStructure = coseSignStructure;
    }

    /**
     * Returns the original signer signature structure (applicable only for COSE_Sign signatures)
     *
     * @return {@link COSEStructure}
     */
    public COSEStructure getSignerSignature() {
        return signerSignature;
    }

    private Key getKey() {
        if (key == null) {
            throw new IllegalStateException("No key has been supplied. COSE verification is not possible!");
        }
        return key;
    }

    /**
     * This method sets the signer's key in order to verify the signature
     *
     * @param key {@link Key} public key of the signer
     */
    public void setKey(Key key) {
        this.key = key;
    }

    /**
     * This method verifies the signature, using the defined {@code key}
     *
     * @return TRUE if the signature is valid, FALSE otherwise
     */
    public boolean verifySignature() {
        try {
            // Create Signature object
            SignatureAlgorithm algorithm = getAlgorithm();
            Signature signatureInstance = Signature.getInstance(algorithm.getJCEId(), DSSSecurityProvider.getSecurityProviderName());

            // Initialize Signature object with the public key
            PublicKey publicKey = (PublicKey) getKey();
            signatureInstance.initVerify(publicKey);

            // Supply the signature input bytes
            byte[] signatureInputBytes = getSignatureInputBytes();
            if (LOG.isTraceEnabled()) {
                LOG.trace("Serialized Sig_structure bytes (hex-encoded):");
                LOG.trace(DSSUtils.toHex(signatureInputBytes));
            }
            signatureInstance.update(signatureInputBytes);

            // Verify the signature
            byte[] signatureBytes = signature.getValueAsBytes();
            signatureBytes = ensureDerEncodedSignature(signatureBytes, algorithm);
            return signatureInstance.verify(signatureBytes);

        } catch (Exception e) {
            LOG.warn("An error occurred on signature validation: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Returns a DataToBeSigned input
     *
     * @return byte array
     */
    public byte[] getSignatureInputBytes() {
        /*
         * Sig_structure = [
         *     context : "Signature" / "Signature1" / "CounterSignature",
         *     body_protected : empty_or_serialized_map,
         *     ? sign_protected : empty_or_serialized_map,
         *     external_aad : bstr,
         *     payload : bstr
         * ]
         */
        final CBORArray array = new CBORArray();

        /*
         * 1. A text string identifying the context of the signature. The context string is:
         *   - "Signature" for signatures using the COSE_Signature structure.
         *   - "Signature1" for signatures using the COSE_Sign1 structure.
         *
         * NOTE: For counter signatures a context string as defined in RFC 9338 is used
         */
        array.add(new UnicodeString(context.getContext()));

        /*
         * 2. The protected attributes from the body structure, encoded in a
         * bstr type. If there are no protected attributes, a zero-length
         * byte string is used.
         */
        if (bodyProtectedHeader != null && !bodyProtectedHeader.isEmpty()) {
            array.add(bodyProtectedHeader.getByteString());
        } else {
            array.add(CBORUtils.EMPTY_BYTE_STRING);
        }

        /*
         * 3. The protected attributes from the signer structure, encoded in a
         * bstr type. If there are no protected attributes, a zero-length
         * byte string is used. This field is omitted for the COSE_Sign1
         * signature structure.
         *
         * NOTE: The field is also omitted for CounterSignature0 and Countersignature0V2 attributes
         */
        if (signerProtectedHeader != null && !signerProtectedHeader.isEmpty()) {
            array.add(signerProtectedHeader.getByteString());
        } else if (COSESignatureType.COSE_SIGN1 != context
                && COSESignatureType.COSE_COUNTER_SIGNATURE0 != context
                && COSESignatureType.COSE_COUNTER_SIGNATURE0_V2 != context) {
            array.add(CBORUtils.EMPTY_BYTE_STRING);
        }

        /*
         * 4. The externally supplied data from the application, encoded in a
         * bstr type. If this field is not supplied, it defaults to a zero-
         * length byte string. (See Section 4.3 for application guidance on
         * constructing this field.)
         */
        if (externallySuppliedData != null) {
            array.add(externallySuppliedData);
        } else {
            array.add(CBORUtils.EMPTY_BYTE_STRING);
        }

        /*
         * 5. The payload to be signed, encoded in a bstr type. The full
         *  payload is used here, independent of how it is transported.
         */
        if (payload != null && payload.isByteString()) {
            array.add(payload);
        } else {
            LOG.warn("No payload found for COSE signature!");
            array.add(CBORUtils.EMPTY_BYTE_STRING);
        }

        /*
         * RFC 9338. CountersignaturesV2 only
         *
         * Countersign_structure = [
         *   context : "CounterSignature" / "CounterSignature0" /
         *             "CounterSignatureV2" / "CounterSignature0V2" /,
         *   body_protected : empty_or_serialized_map,
         *   ? sign_protected : empty_or_serialized_map,
         *   external_aad : bstr,
         *   payload : bstr,
         *   ? other_fields : [+ bstr ]
         * ]
         */
        if (context.isCounterSignatureV2() && otherFields != null) {
            array.add(otherFields);
        }

        return CBORUtils.serializeCborObject(array);
    }

    private byte[] ensureDerEncodedSignature(byte[] signature, SignatureAlgorithm signatureAlgorithm) {
        EncryptionAlgorithm encryptionAlgorithm = signatureAlgorithm.getEncryptionAlgorithm();
        if (EncryptionAlgorithm.ECDSA.isEquivalent(encryptionAlgorithm)) {
            signature = DSSASN1Utils.toStandardDSASignatureValue(signature);
        }
        return signature;
    }

    /**
     * Gets the used SignatureAlgorithm, define within a protected header of the signer
     *
     * @return {@link SignatureAlgorithm}
     */
    public SignatureAlgorithm getAlgorithm() {
        if (signatureAlgorithm != null) {
            return signatureAlgorithm;
        }
        Long algNumber = getAlgorithmHeaderValue();
        if (algNumber == null) {
            throw new DSSException("No 'alg' header found!");
        }

        signatureAlgorithm = SignatureAlgorithm.forCOSE(algNumber, null);
        if (signatureAlgorithm == null) {
            LOG.warn("SignatureAlgorithm '{}' is not supported!", algNumber);
        } else if (EncryptionAlgorithm.EDDSA.equals(signatureAlgorithm.getEncryptionAlgorithm())) {
            signatureAlgorithm = DSSUtils.getEdDSASignatureAlgorithm(getSignatureValue());
        }
        return signatureAlgorithm;
    }

    /**
     * This method returns a value of the {@code 'alg'} header parameter.
     *
     * @return {@link Long}
     */
    protected Long getAlgorithmHeaderValue() {
        return getProtectedHeaderValueAsLong(COSEHeaderParameter.ALG.cbor());
    }

    /**
     * This method returns a Long value extracted from protected header of the signature
     * The method checks the key presence in both body and signer layers and returns the found value,
     * provided there is no conflicting information.
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return {@link Long} value if header is identified, NULL otherwise
     */
    public Long getProtectedHeaderValueAsLong(CBORObject headerKey) {
        CBORObject protectedHeaderValue = getProtectedHeaderValue(headerKey);
        if (protectedHeaderValue != null && (protectedHeaderValue.isNegativeInteger() || protectedHeaderValue.isUnsignedInteger())) {
            return protectedHeaderValue.getValueAsLong();
        }
        return null;
    }

    /**
     * This method returns a String value extracted from protected header of the signature
     * The method checks the key presence in both body and signer layers and returns the found value,
     * provided there is no conflicting information.
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return {@link Long} value if header is identified, NULL otherwise
     */
    public String getProtectedHeaderValueAsString(CBORObject headerKey) {
        CBORObject protectedHeaderValue = getProtectedHeaderValue(headerKey);
        if (protectedHeaderValue != null && (protectedHeaderValue.isUnicodeString())) {
            return protectedHeaderValue.getValueAsString();
        }
        return null;
    }

    /**
     * This method returns a byte array value extracted from protected header of the signature
     * The method checks the key presence in both body and signer layers and returns the found value,
     * provided there is no conflicting information.
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return byte array value if header is identified, NULL otherwise
     */
    public byte[] getProtectedHeaderValueAsBinaries(CBORObject headerKey) {
        CBORObject protectedHeaderValue = getProtectedHeaderValue(headerKey);
        if (protectedHeaderValue != null && (protectedHeaderValue.isByteString())) {
            return protectedHeaderValue.getValueAsBytes();
        }
        return null;
    }

    /**
     * This method returns a CBORArray value extracted from protected header of the signature
     * The method checks the key presence in both body and signer layers and returns the found value,
     * provided there is no conflicting information.
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return {@link CBORArray} value if header is identified, NULL otherwise
     */
    public CBORArray getProtectedHeaderValueAsArray(CBORObject headerKey) {
        CBORObject protectedHeaderValue = getProtectedHeaderValue(headerKey);
        if (protectedHeaderValue != null && (protectedHeaderValue.isArray())) {
            return ((CBORArray) protectedHeaderValue);
        }
        return null;
    }

    /**
     * This method returns a CBORMap value extracted from protected header of the signature.
     * The method checks the key presence in both body and signer layers and returns the found value,
     * provided there is no conflicting information.
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return {@link CBORMap} value if header is identified, NULL otherwise
     */
    public CBORMap getProtectedHeaderValueAsMap(CBORObject headerKey) {
        CBORObject protectedHeaderValue = getProtectedHeaderValue(headerKey);
        if (protectedHeaderValue != null && (protectedHeaderValue.isMap())) {
            return ((CBORMap) protectedHeaderValue);
        }
        return null;
    }

    /**
     * This method returns a value extracted from protected header of the signature.
     * The method checks the key presence in both body and signer layers and returns the found value,
     * provided there is no conflicting information.
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return {@link CBORObject}
     */
    public CBORObject getProtectedHeaderValue(CBORObject headerKey) {
        CBORObject signerProtectedHeaderValue = getSignerProtectedHeaderValue(headerKey);
        // NOTE: for counter signatures only the main protected header is used
        if (context.isCounterSignature() && signerProtectedHeader != null) {
            return signerProtectedHeaderValue;
        }
        CBORObject bodyProtectedHeaderValue = getBodyProtectedHeaderValue(headerKey);
        if (bodyProtectedHeaderValue != null && signerProtectedHeaderValue != null) {
            LOG.info("Same protected header '{}' is present in body and signer structure.", headerKey);
            if (!bodyProtectedHeaderValue.equals(signerProtectedHeaderValue)) {
                LOG.warn("The value of protected header '{}' in body structure does not match the value in signer structure!", headerKey);
                return null;
            }
        }
        return signerProtectedHeaderValue != null ? signerProtectedHeaderValue : bodyProtectedHeaderValue;
    }

    private CBORObject getBodyProtectedHeaderValue(CBORObject headerKey) {
        return bodyProtectedHeader != null ? bodyProtectedHeader.getHeader(headerKey) : null;
    }

    private CBORObject getSignerProtectedHeaderValue(CBORObject headerKey) {
        return signerProtectedHeader != null ? signerProtectedHeader.getHeader(headerKey) : null;
    }

    /**
     * This method returns a protected header directly applying to the signature.
     * For example: a signer layer protected header for COSE_Sign or body layer protected header for COSE_Sign1.
     *
     * @return {@link COSEProtectedHeader}
     */
    public COSEProtectedHeader getSignatureProtectedHeader() {
        // NOTE: Signer layer is present for COSE_Sign signature structure
        switch (context) {
            case COSE_SIGN1:
                return getBodyProtectedHeader();
            case COSE_SIGN:
            case COSE_SIGNATURE:
            case COSE_COUNTER_SIGNATURE:
            case COSE_COUNTER_SIGNATURE_V2:
                return getSignerProtectedHeader();
            default:
                // not applicable in other case
                return null;
        }
    }

    /**
     * Returns an unprotected header 'uHeaders' value, if present
     *
     * @return {@link CBORArray}
     */
    public CBORArray getUHeaders() {
        return getUnprotectedHeaderValueAsArray(COSEHeaderParameter.U_HEADERS.cbor());
    }

    /**
     * This method returns a String value extracted from unprotected header of the signature
     * The method checks the key presence in both body and signer layers and returns the found value,
     * provided there is no conflicting information.
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return {@link Long} value if header is identified, NULL otherwise
     */
    public String getUnprotectedHeaderValueAsString(CBORObject headerKey) {
        CBORObject unprotectedHeaderValue = getUnprotectedHeaderValue(headerKey);
        if (unprotectedHeaderValue != null && (unprotectedHeaderValue.isUnicodeString())) {
            return unprotectedHeaderValue.getValueAsString();
        }
        return null;
    }

    /**
     * This method returns a byte array value extracted from unprotected header of the signature
     * The method checks the key presence in both body and signer layers and returns the found value,
     * provided there is no conflicting information.
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return byte array value if header is identified, NULL otherwise
     */
    public byte[] getUnprotectedHeaderValueAsBinaries(CBORObject headerKey) {
        CBORObject unprotectedHeaderValue = getUnprotectedHeaderValue(headerKey);
        if (unprotectedHeaderValue != null && (unprotectedHeaderValue.isByteString())) {
            return unprotectedHeaderValue.getValueAsBytes();
        }
        return null;
    }

    /**
     * This method returns a CBORArray value extracted from unprotected header of the signature
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return {@link CBORArray} value if header is identified, NULL otherwise
     */
    public CBORArray getUnprotectedHeaderValueAsArray(CBORObject headerKey) {
        CBORObject unprotectedHeaderValue = getUnprotectedHeaderValue(headerKey);
        if (unprotectedHeaderValue != null && (unprotectedHeaderValue.isArray())) {
            return ((CBORArray) unprotectedHeaderValue);
        }
        return null;
    }

    /**
     * This method returns a value extracted from unprotected header of the signature
     *
     * @param headerKey {@link CBORObject} identifier of the header
     * @return {@link CBORObject}
     */
    public CBORObject getUnprotectedHeaderValue(CBORObject headerKey) {
        CBORObject signerUnprotectedHeaderValue = getSignerUnprotectedHeaderValue(headerKey);
        // NOTE: for counter signatures only the main unprotected header is used
        if (context.isCounterSignature() && signerUnprotectedHeader != null) {
            return signerUnprotectedHeaderValue;
        }
        CBORObject bodyUnprotectedHeaderValue = getBodyUnprotectedHeaderValue(headerKey);
        if (bodyUnprotectedHeaderValue != null && signerUnprotectedHeaderValue != null) {
            LOG.info("Same unprotected header '{}' is present in body and signer structure.", headerKey);
            if (!bodyUnprotectedHeaderValue.equals(signerUnprotectedHeaderValue)) {
                LOG.warn("The value of unprotected header '{}' in body structure does not match the value in signer structure!", headerKey);
                return null;
            }
        }
        return signerUnprotectedHeaderValue != null ? signerUnprotectedHeaderValue : bodyUnprotectedHeaderValue;
    }

    private CBORObject getBodyUnprotectedHeaderValue(CBORObject headerKey) {
        return bodyUnprotectedHeader != null ? bodyUnprotectedHeader.getHeader(headerKey) : null;
    }

    private CBORObject getSignerUnprotectedHeaderValue(CBORObject headerKey) {
        return signerUnprotectedHeader != null ? signerUnprotectedHeader.getHeader(headerKey) : null;
    }

}
