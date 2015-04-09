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
package eu.europa.esig.dss.validation;

import org.apache.commons.codec.binary.Hex;

/**
 * Reference a Certificate
 *
 *
 */

public class CertificateRef {

    private String digestAlgorithm;
    private byte[] digestValue;
    private String issuerName;
    private String issuerSerial;

    /**
     * @return
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * @param digestAlgorithm
     */
    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * @return
     */
    public byte[] getDigestValue() {
        return digestValue;
    }

    /**
     * @param digestValue
     */
    public void setDigestValue(byte[] digestValue) {
        this.digestValue = digestValue;
    }

    /**
     * @return
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName
     */
    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * @return
     */
    public String getIssuerSerial() {
        return issuerSerial;
    }

    /**
     * @param issuerSerial
     */
    public void setIssuerSerial(String issuerSerial) {
        this.issuerSerial = issuerSerial;
    }

    @Override
    public String toString() {

        return "CertificateRef[issuerName=" + issuerName + ",issuerSerial=" + issuerSerial + ",digest=" + Hex.encodeHexString(digestValue) + "]";
    }
}
