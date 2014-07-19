/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.ocsp;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.ec.markt.dss.DSSRevocationUtils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;

/**
 * Reference an OCSPResponse
 *
 * @version $Revision$ - $Date$
 */

public class OCSPRef {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(OCSPRef.class);

    private final DigestAlgorithm digestAlgorithm;

    private final byte[] digestValue;

    private final boolean matchOnlyBasicOCSPResponse;

    /**
     * The default constructor for OCSPRef.
     */
    public OCSPRef(OcspResponsesID ocsp, boolean matchOnlyBasicOCSPResponse) {

        final OtherHash otherHash = ocsp.getOcspRepHash();
        this.digestAlgorithm = DigestAlgorithm.forOID(otherHash.getHashAlgorithm().getAlgorithm());
        this.digestValue = ocsp.getOcspRepHash().getHashValue();
        this.matchOnlyBasicOCSPResponse = matchOnlyBasicOCSPResponse;
    }

    /**
     * The default constructor for OCSPRef.
     */
    public OCSPRef(DigestAlgorithm algorithm, byte[] digestValue, boolean matchOnlyBasicOCSPResponse) {

        this.digestAlgorithm = algorithm;
        this.digestValue = digestValue;
        this.matchOnlyBasicOCSPResponse = matchOnlyBasicOCSPResponse;
    }

    /**
     * @param ocspResp
     * @return
     */
    public boolean match(BasicOCSPResp ocspResp) {

        try {

            MessageDigest digest = DSSUtils.getMessageDigest(digestAlgorithm);
            if (matchOnlyBasicOCSPResponse) {

                digest.update(ocspResp.getEncoded());
            } else {

                digest.update(DSSRevocationUtils.fromBasicToResp(ocspResp).getEncoded());
            }
            byte[] computedValue = digest.digest();
            if (LOG.isInfoEnabled()) LOG.info("Compare " + DSSUtils.encodeHexString(digestValue) + " to computed value " + DSSUtils.encodeHexString(computedValue) + " of " +
                  "BasicOCSPResp produced at " + ocspResp
                  .getProducedAt());

            return Arrays.equals(digestValue, computedValue);
        } catch (NoSuchAlgorithmException ex) {

            throw new RuntimeException("Maybe BouncyCastle provider is not installed ?", ex);
        } catch (IOException ex) {

            throw new RuntimeException(ex);
        }
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public byte[] getDigestValue() {
        return digestValue;
    }
}
