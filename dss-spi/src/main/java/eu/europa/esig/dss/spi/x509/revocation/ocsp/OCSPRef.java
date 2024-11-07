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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.esf.OcspResponsesID;

import java.util.Date;

/**
 * Reference an OCSPResponse
 */
public class OCSPRef extends RevocationRef<OCSP> {

    private static final long serialVersionUID = -4757221403735075782L;

    /** OCSP's production time */
    private Date producedAt;

    /** The OCSP Responder Id */
    private ResponderId responderId;

    /**
     * The default constructor for OCSPRef.
     *
     * @param digest {@link Digest}
     * @param producedAt {@link Date}
     * @param responderId {@link ResponderId}
     */
    public OCSPRef(Digest digest, Date producedAt, ResponderId responderId) {
        this.digest = digest;
        this.producedAt = producedAt;
        this.responderId = responderId;
    }

    /**
     * The default constructor for OCSPRef.
     *
     * @param ocspResponsesID {@link OcspResponsesID}
     */
    public OCSPRef(final OcspResponsesID ocspResponsesID) {
        this.digest = DSSRevocationUtils.getDigest(ocspResponsesID.getOcspRepHash());
        this.producedAt = DSSASN1Utils.getDate(ocspResponsesID.getOcspIdentifier().getProducedAt());
        this.responderId = DSSRevocationUtils.getDSSResponderId(ocspResponsesID.getOcspIdentifier().getOcspResponderID());
    }

    /**
     * Gets the OCSP's production time
     *
     * @return {@link Date}
     */
    public Date getProducedAt() {
        return producedAt;
    }

    /**
     * Gets the Responder Id
     *
     * @return {@link ResponderId}
     */
    public ResponderId getResponderId() {
        return responderId;
    }

    @Override
    protected Identifier createIdentifier() {
        return new OCSPRefIdentifier(this);
    }

    @Override
    public String toString() {
        if (responderId.getX500Principal() != null) {
            return "OCSP Reference produced at [" + DSSUtils.formatDateToRFC(producedAt) + "] "
                    + "with Responder Name: [" + responderId.getX500Principal() + "]";
        } else {
            return "OCSP Reference produced at [" + DSSUtils.formatDateToRFC(producedAt) + "] "
                    + "with Responder key 64base: [" + Utils.toBase64(responderId.getSki()) + "]";
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((producedAt == null) ? 0 : producedAt.hashCode());
        result = prime * result + ((responderId == null) ? 0 : responderId.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        OCSPRef other = (OCSPRef) obj;
        if (producedAt == null) {
            if (other.producedAt != null) {
                return false;
            }
        } else if (!producedAt.equals(other.producedAt)) {
            return false;
        }
        if (responderId == null) {
            if (other.responderId != null) {
                return false;
            }
        } else if (!responderId.equals(other.responderId)) {
            return false;
        }
        return true;
    }

}
