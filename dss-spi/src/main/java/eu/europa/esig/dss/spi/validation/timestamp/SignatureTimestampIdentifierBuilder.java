/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.validation.timestamp;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;
import eu.europa.esig.dss.spi.x509.tsp.TimestampIdentifierBuilder;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.util.Objects;

/**
 * Builds an identifier for a time-stamp token encapsulated within a signature
 *
 */
public class SignatureTimestampIdentifierBuilder extends TimestampIdentifierBuilder {

    private static final long serialVersionUID = -1948364785002670303L;

    /** Prefix string for the order of attribute value */
    private static final String ORDER_OF_ATTRIBUTE_PREFIX = "-OOA-";

    /** Prefix string for order within attribute value */
    private static final String ORDER_WITHIN_ATTRIBUTE_PREFIX = "-OWA-";

    /** Corresponding signature of the time-stamp */
    private AdvancedSignature signature;

    /** Attribute encapsulating the time-stamp token */
    private SignatureAttribute attribute;

    /** Position of the attribute within the signature */
    private Integer orderOfAttribute;

    /** Position of the current time-stamp within time-stamp attribute */
    private Integer orderWithinAttribute;

    /**
     * Default constructor to build an identifier for time-stamp token binaries from a signature
     *
     * @param timestampTokenBinaries binaries of the time-stamp token
     */
    public SignatureTimestampIdentifierBuilder(final byte[] timestampTokenBinaries) {
        super(timestampTokenBinaries);
    }

    /**
     * Constructor to build an identifier for a time-stamp token from a signature
     *
     * @param timeStampToken {@link TimeStampToken}
     */
    public SignatureTimestampIdentifierBuilder(final TimeStampToken timeStampToken) {
        this(getEncoded(timeStampToken));
    }

    private static byte[] getEncoded(TimeStampToken timeStampToken) {
        Objects.requireNonNull(timeStampToken, "TimeStampToken cannot be null!");
        try {
            return timeStampToken.getEncoded();
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to get time-stamp token binaries! Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Sets signature corresponding to the time-stamp token
     *
     * @param signature {@link AdvancedSignature}
     * @return this {@link SignatureTimestampIdentifierBuilder}
     */
    public SignatureTimestampIdentifierBuilder setSignature(AdvancedSignature signature) {
        this.signature = signature;
        return this;
    }

    /**
     * Sets a signature attribute encapsulating the time-stamp token
     *
     * @param attribute {@link SignatureAttribute}
     * @return this {@link SignatureTimestampIdentifierBuilder}
     */
    public SignatureTimestampIdentifierBuilder setAttribute(SignatureAttribute attribute) {
        this.attribute = attribute;
        return this;
    }

    /**
     * Sets position of the time-stamp carrying attribute within the signature
     *
     * @param orderOfAttribute position of the attribute
     * @return this {@link SignatureTimestampIdentifierBuilder}
     */
    public SignatureTimestampIdentifierBuilder setOrderOfAttribute(Integer orderOfAttribute) {
        this.orderOfAttribute = orderOfAttribute;
        return this;
    }

    /**
     * Sets position of the time-stamp within its carrying attribute
     *
     * @param orderWithinAttribute position of the time-stamp within the attribute
     * @return this {@link SignatureTimestampIdentifierBuilder}
     */
    public SignatureTimestampIdentifierBuilder setOrderWithinAttribute(Integer orderWithinAttribute) {
        this.orderWithinAttribute = orderWithinAttribute;
        return this;
    }

    @Override
    protected String getTimestampPosition() {
        StringBuilder sb = new StringBuilder();
        if (signature != null) {
            sb.append(signature.getId());
        }
        if (attribute != null) {
            sb.append(attribute.getIdentifier().asXmlId());
        }
        if (orderOfAttribute != null) {
            sb.append(ORDER_OF_ATTRIBUTE_PREFIX);
            sb.append(orderOfAttribute);
        }
        if (orderWithinAttribute != null) {
            sb.append(ORDER_WITHIN_ATTRIBUTE_PREFIX);
            sb.append(orderWithinAttribute);
        }
        return sb.toString();
    }

}
