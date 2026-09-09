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

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.CBAdESUtils;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extracts and stores CRLs from a CB-AdES signature
 *
 */
public class CBAdESCRLSource extends OfflineCRLSource {

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESCRLSource.class);

    /** Represents the unsigned 'uHeaders' header */
    private final transient CBAdESUHeaders uHeaders;

    /**
     * Default constructor
     *
     * @param uHeaders {@link CBAdESUHeaders} containing the unsigned properties of the signature
     */
    public CBAdESCRLSource(final CBAdESUHeaders uHeaders) {
        this.uHeaders = uHeaders;

        extractUHeaders();
    }

    private void extractUHeaders() {
        if (uHeaders == null || !uHeaders.isExist()) {
            return;
        }

        for (CBAdESAttribute attribute : uHeaders.getAttributes()) {
            extractValidationData(attribute);
            extractCompleteRevocationRefs(attribute);
        }
    }

    private void extractValidationData(CBAdESAttribute attribute) {
        if (COSEHeaderParameter.VAL_DATA.cbor().equals(attribute.getHeaderId())) {
            CBORValue valData = attribute.getValue();
            if (valData.isMap()) {
                CBORValue rVals = valData.getAsMapOrNull(COSEHeaderParameter.VAL_DATA_R_VALS.cbor());
                if (rVals != null && rVals.size() != 0) {
                    extractRevocationValues(rVals, RevocationOrigin.ANY_VALIDATION_DATA);
                }
            } else {
                LOG.warn("The value of header 'valData' shall be represented by a CBOR Map! Entry is skipped.");
            }
        }
    }

    private void extractRevocationValues(CBORValue rVals, RevocationOrigin origin) {
        CBORValue crlVals = rVals.getAsArrayOrNull(COSEHeaderParameter.R_VALS_CRL_VALS.cbor());
        if (crlVals != null && crlVals.size() != 0) {
            for (CBORValue pkiOb : crlVals.getElements()) {
                if (pkiOb.isMap()) {
                    extractCRL(pkiOb, origin);
                } else {
                    LOG.warn("The header 'pkiOb' shall be represented by a CBOR Map! The entry is skipped.");
                }
            }
        }
    }

    private void extractCRL(CBORValue pkiOb, RevocationOrigin origin) {
        byte[] val = CBAdESUtils.extractDerEncodedPkiObject(pkiOb);
        if (Utils.isArrayNotEmpty(val)) {
            try {
                addBinary(CRLUtils.buildCRLBinary(val), origin);
            } catch (Exception e) {
                LOG.warn("Unable to extract CRL from '{}'. Reason : {}", Utils.toBase64(val), e.getMessage(), e);
            }
        }
    }

    private void extractCompleteRevocationRefs(CBAdESAttribute attribute) {
        if (COSEHeaderParameter.REFS.cbor().equals(attribute.getHeaderId())) {
            CBORValue refs = attribute.getValue();
            if (refs.isMap()) {
                CBORValue rRefs = refs.getAsMapOrNull(COSEHeaderParameter.REFS_R_REFS.cbor());
                if (rRefs != null && rRefs.size() != 0) {
                    extractRevocationRefs(rRefs, RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
                }
            } else {
                LOG.warn("The value of header 'refs' shall be represented by a CBOR Map! Entry is skipped.");
            }
        }
    }

    private void extractRevocationRefs(CBORValue rRefs, RevocationRefOrigin origin) {
        CBORValue crlRefs = rRefs.getAsArrayOrNull(COSEHeaderParameter.R_REFS_CRL_REF.cbor());
        if (crlRefs != null) {
            for (CBORValue crlRefObject : crlRefs.getElements()) {
                if (crlRefObject.isMap()) {
                    CRLRef crlRef = CBAdESUtils.createCRLRef(crlRefObject);
                    if (crlRef != null) {
                        addRevocationReference(crlRef, origin);
                    }
                } else {
                    LOG.warn("The header 'CRLRef' shall be represented by a CBOR Map! The entry is skipped.");
                }
            }
        }
    }

}
