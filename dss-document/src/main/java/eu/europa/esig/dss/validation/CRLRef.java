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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.x500.X500Name;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;

/**
 * Reference to a X509CRL
 *
 */
public final class CRLRef {

    private X500Name crlIssuer;
    private Date crlIssuedTime;
    private BigInteger crlNumber;
    private DigestAlgorithm digestAlgorithm;
    private byte[] digestValue;

    /**
     * The default constructor for CRLRef.
     */
    public CRLRef(DigestAlgorithm digestAlgorithm, byte[] digestValue) {
    	this.digestAlgorithm = digestAlgorithm;
    	this.digestValue = digestValue;
    }

    /**
     * The default constructor for CRLRef.
     *
     * @param cmsRef
     * @throws ParseException
     */
    public CRLRef(CrlValidatedID cmsRef) {
        try {

            final CrlIdentifier crlIdentifier = cmsRef.getCrlIdentifier();
            if (crlIdentifier != null) {
                crlIssuer = crlIdentifier.getCrlIssuer();
                crlIssuedTime = crlIdentifier.getCrlIssuedTime().getDate();
                crlNumber = crlIdentifier.getCrlNumber();
            }
            final OtherHash crlHash = cmsRef.getCrlHash();

            digestAlgorithm = DigestAlgorithm.forOID(crlHash.getHashAlgorithm().getAlgorithm());
            digestValue = crlHash.getHashValue();
        } catch (ParseException ex) {
            throw new DSSException(ex);
        }
    }

    /**
     * @param crl
     * @return
     */
    public boolean match(X509CRL crl) {
        try {
            MessageDigest digest = DSSUtils.getMessageDigest(digestAlgorithm);
            byte[] computedValue = digest.digest(crl.getEncoded());
            return Arrays.equals(digestValue, computedValue);
        } catch (CRLException ex) {
            throw new DSSException(ex);
        }
    }

    /**
     * @return
     */
    public X500Name getCrlIssuer() {
        return crlIssuer;
    }

    /**
     * @return
     */
    public Date getCrlIssuedTime() {
        return crlIssuedTime;
    }

    /**
     * @return
     */
    public BigInteger getCrlNumber() {
        return crlNumber;
    }

    /**
     * @return
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * @return
     */
    public byte[] getDigestValue() {
        return digestValue;
    }

}
