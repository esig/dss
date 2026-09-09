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

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSESignature;
import eu.europa.esig.dss.cbades.COSEUnprotectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.SignatureProperties;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

/**
 * Represents the list of components present inside the unprotected 'uHeaders' header
 *
 */
public class CBAdESUHeaders implements SignatureProperties<CBAdESUHeadersComponent> {

    private static final long serialVersionUID = 2141375341919119408L;

    /** The COSE signature */
    private final CBORSignature cose;

    /** The list of 'uHeaders' components */
    private List<CBAdESUHeadersComponent> components;

    /**
     * The default constructor
     *
     * @param cose {@link CBORSignature} signature
     */
    public CBAdESUHeaders(final CBORSignature cose) {
        this.cose = cose;
    }

    @Override
    public boolean isExist() {
        return Utils.isCollectionNotEmpty(getAttributes());
    }

    @Override
    public List<CBAdESUHeadersComponent> getAttributes() {
        if (components == null) {
            components = new ArrayList<>();
            CBORValue uHeaders = getCBORValue();
            if (uHeaders != null && uHeaders.size() != 0) {
                for (int i = 0; i < uHeaders.size(); i++) {
                    CBORValue uHeadersEntry = uHeaders.get(i);
                    CBAdESUHeadersComponent component = CBAdESUHeadersComponent.build(uHeadersEntry, i);
                    if (component != null) {
                        components.add(component);
                    }
                    // else : unable to create, skip
                }
            }
        }
        return components;
    }

    /**
     * Gets 'uHeaders' representation in a CBORArray
     *
     * @return {@link CBORArray}
     * @deprecated since DSS 6.6. Please use {@link #getCBORValue()} instead.
     */
    @Deprecated
    public CBORArray getCBORArray() {
        CBORValue cborValue = getCBORValue();
        if (cborValue != null) {
            return new CBORArray(cborValue);
        }
        return null;
    }

    /**
     * Gets 'uHeaders' representation in a CBORArray
     *
     * @return {@link CBORValue}
     */
    public CBORValue getCBORValue() {
        COSEUnprotectedHeader unprotectedHeader = getUnprotectedHeader();
        if (unprotectedHeader != null && !unprotectedHeader.isEmpty()) {
            return unprotectedHeader.getValue().getAsArrayOrNull(COSEHeaderParameter.U_HEADERS.cbor());
        }
        return null;
    }

    /**
     * Adds a new entry to the 'uHeaders' array
     *
     * @param headerKey        {@link CBORObject} representing the name of the 'uHeaders' entry
     * @param value            {@link CBORObject} represents a value of the 'uHeaders' entry
     * @deprecated since DSS 6.6. Please use {@link #addComponent(CBORValue, CBORValue)}
     */
    @Deprecated
    public void addComponent(CBORObject headerKey, CBORObject value) {
        addComponent(headerKey.toCBORValue(), value.toCBORValue());
    }

    /**
     * Adds a new entry to the 'uHeaders' array
     *
     * @param headerKey        {@link CBORValue} representing the name of the 'uHeaders' entry
     * @param value            {@link CBORValue} represents a value of the 'uHeaders' entry
     */
    public void addComponent(CBORValue headerKey, CBORValue value) {
        CBORValue uHeaders = getUHeadersToEdit();
        CBORValue etsiEntry = getComponent(headerKey, value);
        uHeaders.editArray().add(etsiEntry);
    }

    private CBORValue getComponent(CBORValue headerKey, CBORValue value) {
        return CBOR.bytes(CBOR.map()
                .put(headerKey, value)
                .value().encodeToBytes());
    }

    /**
     * Gets a list of 'uHeaders' entries with matching {@code headerId}
     *
     * @param headerId {@link Long} representing an 'uHeaders' entry identifier
     * @return a list of {@link CBAdESUHeadersComponent}
     * @deprecated since DSS 6.6. Use {@link #getUnsignedPropertiesWithHeaderId(CBORValue)}
     */
    @Deprecated
    public List<CBAdESUHeadersComponent> getUnsignedPropertiesWithHeaderId(CBORObject headerId) {
        return getUnsignedPropertiesWithHeaderId(headerId.toCBORValue());
    }

    /**
     * Gets a list of 'uHeaders' entries with matching {@code headerId}
     *
     * @param headerId {@link Long} representing an 'uHeaders' entry identifier
     * @return a list of {@link CBAdESUHeadersComponent}
     */
    public List<CBAdESUHeadersComponent> getUnsignedPropertiesWithHeaderId(CBORValue headerId) {
        List<CBAdESUHeadersComponent> componentsWithHeaderName = new ArrayList<>();
        for (CBAdESUHeadersComponent attribute : getAttributes()) {
            if (headerId.equals(attribute.getHeaderId())) {
                componentsWithHeaderName.add(attribute);
            }
        }
        return componentsWithHeaderName;
    }

    private CBORValue getUHeadersToEdit() {
        COSEUnprotectedHeader unprotectedHeader = getUnprotectedHeader();

        clearCachedAttributes();
        if (unprotectedHeader.isEmpty()) {
            assignUnprotectedHeader(unprotectedHeader);
        }

        CBORValue uHeaders = unprotectedHeader.getHeader(COSEHeaderParameter.U_HEADERS.cbor());
        if (uHeaders != null) {
            if (!uHeaders.isArray()) {
                throw new IllegalInputException("'uHeaders' header parameter shall be of type CBORArray!");
            }
            // continue

        } else {
            uHeaders = CBOR.array(1).value();
            unprotectedHeader.put(COSEHeaderParameter.U_HEADERS.cbor(), uHeaders);
        }
        return uHeaders;
    }

    private COSEUnprotectedHeader getUnprotectedHeader() {
        // NOTE: unprotected header map is initialized in all applicable cases
        switch (cose.getContext()) {
            case COSE_SIGN1:
                return cose.getBodyUnprotectedHeader();
            case COSE_SIGN:
            case COSE_SIGNATURE:
            case COSE_COUNTER_SIGNATURE:
            case COSE_COUNTER_SIGNATURE_V2:
                return cose.getSignerUnprotectedHeader();
            default:
                // not applicable in other case (init empty)
                return new COSEUnprotectedHeader();
        }
    }

    private void assignUnprotectedHeader(COSEUnprotectedHeader unprotectedHeader) {
        switch (cose.getContext()) {
            case COSE_SIGN1:
                COSESign1 coseSign1 = (COSESign1) cose.getCoseSignStructure();
                coseSign1.setUnprotectedHeader(unprotectedHeader);
                break;

            case COSE_SIGN:
            case COSE_COUNTER_SIGNATURE:
            case COSE_COUNTER_SIGNATURE_V2:
                COSESignature signerSignature = (COSESignature) cose.getSignerSignature();
                signerSignature.setUnprotectedHeader(unprotectedHeader);
                break;

            default:
                throw new UnsupportedOperationException(
                        String.format("The context '%s' is not supported!", cose.getContext()));
        }
    }

    private void clearCachedAttributes() {
        this.components = null;
    }

    /**
     * Replaces the given component within the 'uHeaders' header array
     *
     * @param uHeader {@link CBAdESUHeadersComponent} to replace
     */
    public void replaceComponent(CBAdESUHeadersComponent uHeader) {
        CBORValue uHeaders = getUHeadersToEdit();
        for (int i = 0; i < uHeaders.size(); i++) {
            CBORValue item = uHeaders.get(i);
            CBAdESUHeadersComponent currentComponent = CBAdESUHeadersComponent.build(item, i);
            if (uHeader.equals(currentComponent)) {
                uHeaders.editArray().set(i, uHeader.getComponent());
                break;
            }
        }
    }

    /**
     * Removes the 'uHeaders' components with the given {@code headerName}
     *
     * @param headerId {@link CBORObject} identifier of the 'uHeaders' entry to remove
     * @deprecated since DSS 6.6. Use {@link #removeComponent(CBORValue)}
     */
    @Deprecated
    public void removeComponent(CBORObject headerId) {
        removeComponent(headerId.toCBORValue());
    }

    /**
     * Removes the 'uHeaders' components with the given {@code headerName}
     *
     * @param headerId {@link CBORValue} identifier of the 'uHeaders' entry to remove
     */
    public void removeComponent(CBORValue headerId) {
        CBORValue uHeaders = getUHeadersToEdit();
        if (uHeaders != null && uHeaders.size() != 0) {
            ListIterator<CBORValue> iterator = getBackwardIterator(uHeaders);
            while (iterator.hasPrevious()) {
                removeLastIfMatches(uHeaders, iterator, headerId);
            }
        }
    }

    /**
     * Removes the last 'uHeaders' item if the name matches to the given {@code headerName}
     *
     * @param headerId {@link CBORObject} identifier of the 'uHeaders' entry to remove
     * @deprecated since DSS 6.6. Use {@link #removeComponent(CBORValue)}
     */
    @Deprecated
    public void removeLastComponent(CBORObject headerId) {
        removeLastComponent(headerId.toCBORValue());
    }

    /**
     * Removes the last 'uHeaders' item if the name matches to the given {@code headerName}
     *
     * @param headerId {@link CBORValue} identifier of the 'uHeaders' entry to remove
     */
    public void removeLastComponent(CBORValue headerId) {
        CBORValue uHeaders = getUHeadersToEdit();
        if (uHeaders != null && uHeaders.size() != 0) {
            ListIterator<CBORValue> iterator = getBackwardIterator(uHeaders);
            removeLastIfMatches(uHeaders, iterator, headerId);
        }
    }

    private ListIterator<CBORValue> getBackwardIterator(CBORValue uHeaders) {
        return uHeaders.getElements().listIterator(uHeaders.size());
    }

    private void removeLastIfMatches(CBORValue uHeaders, ListIterator<CBORValue> iterator, CBORValue headerId) {
        CBORValue originalObject = iterator.previous();
        CBORValue objectMapRepresentation = null;
        if (originalObject.isByteString()) {
            objectMapRepresentation = CBORUtils.parseCbor(originalObject.asBytes());
        } else if (originalObject.isMap()) {
            objectMapRepresentation = originalObject;
        }
        if (objectMapRepresentation != null && objectMapRepresentation.isMap()
                && objectMapRepresentation.getKeys().contains(headerId)) {
            uHeaders.editArray().remove(originalObject);
        }
    }

}
