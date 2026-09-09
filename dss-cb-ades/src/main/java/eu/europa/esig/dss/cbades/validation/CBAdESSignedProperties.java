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

import eu.europa.ec.digit.cddl4j.cbor.CBORMapEntry;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.spi.validation.SignatureProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a list of CB-AdES signed properties (protected header)
 *
 */
public class CBAdESSignedProperties implements SignatureProperties<CBAdESAttribute> {

    private static final long serialVersionUID = -2202028912414313535L;

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESSignedProperties.class);

    /** Represent the protected header of the signature's body structure */
    private final COSEProtectedHeader bodyProtectedHeader;

    /** Represent the protected header of the signature's signer structure */
    private final COSEProtectedHeader signerProtectedHeader;

    /**
     * Default constructor
     *
     * @param bodyProtectedHeader {@link COSEProtectedHeader} of the COSE body structure
     * @param signerProtectedHeader {@link COSEProtectedHeader} of the COSE signer structure (only for COSE_Sign)
     */
    public CBAdESSignedProperties(COSEProtectedHeader bodyProtectedHeader, COSEProtectedHeader signerProtectedHeader) {
        if (bodyProtectedHeader == null && signerProtectedHeader == null) {
            throw new NullPointerException("Either bodyProtectedHeader or signerProtectedHeader shall be defined!");
        }
        this.bodyProtectedHeader = bodyProtectedHeader;
        this.signerProtectedHeader = signerProtectedHeader;
    }

    /**
     * Constructor for counter signature
     *
     * @param signerProtectedHeader {@link COSEProtectedHeader} of the COSE counter signature structure
     */
    public CBAdESSignedProperties(COSEProtectedHeader signerProtectedHeader) {
        this(null, signerProtectedHeader);
    }

    @Override
    public boolean isExist() {
        return bodyProtectedHeader != null || signerProtectedHeader != null;
    }

    @Override
    public List<CBAdESAttribute> getAttributes() {
        final List<CBAdESAttribute> attributes = new ArrayList<>();

        if (bodyProtectedHeader != null) {
            for (CBORMapEntry entry : bodyProtectedHeader.getValue().getEntries()) {
                attributes.add(new CBAdESAttribute(entry.key(), entry.value()));
            }
        }
        if (signerProtectedHeader != null) {
            for (CBORMapEntry entry : signerProtectedHeader.getValue().getEntries()) {
                if (bodyProtectedHeader != null && bodyProtectedHeader.getValue().containsKey(entry.key())) {
                    if (bodyProtectedHeader.getHeader(entry.key()).equals(entry.value())) {
                        LOG.warn("The header with key '{}' is present in both body and signer protected header!",
                                entry.key());
                    } else {
                        LOG.warn("Conflict between headers with key '{}' from body and signer protected header! " +
                                "Ignore entry.", entry.key());
                        continue;
                    }
                }
                attributes.add(new CBAdESAttribute(entry.key(), entry.value()));
            }
        }

        return attributes;
    }

}
