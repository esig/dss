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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;

import java.math.BigInteger;
import java.util.Date;

/**
 * Wrapper class for XML orphan certificate
 *
 */
public class OrphanCertificateTokenWrapper extends OrphanTokenWrapper<XmlOrphanCertificateToken> {

    /**
     * Default constructor
     *
     * @param orphanToken {@link XmlOrphanCertificateToken}
     */
    public OrphanCertificateTokenWrapper(XmlOrphanCertificateToken orphanToken) {
        super(orphanToken);
    }

    /**
     * Returns the certificate's Distinguished Name (by RFC 2253)
     *
     * @return {@link String}
     */
    public String getCertificateDN() {
        DistinguishedNameListWrapper distinguishedNameListWrapper = new DistinguishedNameListWrapper(
                orphanToken.getSubjectDistinguishedName());
        return distinguishedNameListWrapper.getValue("RFC2253");
    }

    /**
     * Returns the certificate issuer's Distinguished Name (by RFC 2253)
     *
     * @return {@link String}
     */
    public String getCertificateIssuerDN() {
        DistinguishedNameListWrapper distinguishedNameListWrapper = new DistinguishedNameListWrapper(
                orphanToken.getIssuerDistinguishedName());
        return distinguishedNameListWrapper.getValue("RFC2253");
    }

    /**
     * Returns the serial number of the certificate
     *
     * @return {@link String}
     */
    public String getSerialNumber() {
        BigInteger serialNumber = orphanToken.getSerialNumber();
        return serialNumber == null ? "" : serialNumber.toString();
    }

    /**
     * Returns the certificate's notBefore date (the date the certificate cannot be used before)
     *
     * @return {@link Date} notBefore
     */
    public Date getNotBefore() {
        return orphanToken.getNotBefore();
    }

    /**
     * Returns the certificate's notAfter date (the date the certificate cannot be used after)
     *
     * @return {@link Date} notAfter
     */
    public Date getNotAfter() {
        return orphanToken.getNotAfter();
    }

    /**
     * Returns a string identifier of the certificate's public key
     *
     * @return {@link String} public key's identifier
     */
    public String getEntityKey() {
        return orphanToken.getEntityKey();
    }

    /**
     * Returns if the certificate is trusted
     *
     * @return TRUE if the certificate is trusted, FALSE otherwise
     */
    public boolean isTrusted() {
        return orphanToken.isTrusted();
    }

    /**
     * Returns if the certificate is self-signed
     *
     * @return TRUE if the certificate is self-signed, FALSE otherwise
     */
    public boolean isSelfSigned() {
        return orphanToken.isSelfSigned();
    }

    @Override
    public byte[] getBinaries() {
        return orphanToken.getBase64Encoded();
    }

    @Override
    public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
        return orphanToken.getDigestAlgoAndValue();
    }

}
