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
package eu.europa.esig.dss.cms.stream.bc;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;

/**
 * DigestCalculatorProvider implementation based on {@code DSSMessageDigestCalculator}
 *
 */
public class MessageDigestCalculatorProvider implements DigestCalculatorProvider {

    private static final Logger LOG = LoggerFactory.getLogger(MessageDigestCalculatorProvider.class);

    /**
     * Default constructor
     */
    public MessageDigestCalculatorProvider() {
        // empty
    }

    @Override
    public DigestCalculator get(final AlgorithmIdentifier algorithm) {
        final DSSMessageDigestCalculator messageDigestCalculator = getDSSMessageDigestCalculator(algorithm);

        return new DigestCalculator() {
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return algorithm;
            }

            public OutputStream getOutputStream() {
                if (messageDigestCalculator != null) {
                    return messageDigestCalculator.getOutputStream();
                } else {
                    return Utils.nullOutputStream();
                }
            }

            public byte[] getDigest() {
                if (messageDigestCalculator != null) {
                    return messageDigestCalculator.getMessageDigest(getDigestAlgorithm(algorithm)).getValue();
                } else {
                    return DSSUtils.EMPTY_BYTE_ARRAY;
                }
            }
        };
    }

    private DSSMessageDigestCalculator getDSSMessageDigestCalculator(AlgorithmIdentifier algorithm) {
        try {
            DigestAlgorithm digestAlgorithm = getDigestAlgorithm(algorithm);
            return new DSSMessageDigestCalculator(digestAlgorithm);
        } catch (Exception e) {
            LOG.warn("Unable to retrieve digest value for an algorithm '{}'. Reason : {}",
                    algorithm.getAlgorithm().getId(), e.getMessage());
            return null;
        }
    }

    private DigestAlgorithm getDigestAlgorithm(AlgorithmIdentifier algorithm) {
        return DigestAlgorithm.forOID(algorithm.getAlgorithm().getId());
    }

}
