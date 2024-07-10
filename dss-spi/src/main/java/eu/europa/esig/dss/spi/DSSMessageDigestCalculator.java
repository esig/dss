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
package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class is used to compute {@code DSSMessageDigest} based on the provided input
 *
 */
public class DSSMessageDigestCalculator {

    /** The DigestAlgorithm used to compute message-digest */
    private final DigestAlgorithm digestAlgorithm;

    /** The java message-digest implementation used in calculations */
    private final MessageDigest messageDigest;

    /**
     * Default constructor
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for message-digest computation
     */
    public DSSMessageDigestCalculator(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
        this.messageDigest = toMessageDigest(digestAlgorithm);
    }

    private MessageDigest toMessageDigest(DigestAlgorithm digestAlgorithm) {
        try {
            return digestAlgorithm.getMessageDigest();
        } catch (NoSuchAlgorithmException e) {
            throw new DSSException(String.format("Unable to build MessageDigest for the algorithm '%s' : %s",
                    digestAlgorithm.getName(), e.getMessage()), e);
        }
    }

    /**
     * Updates the digest using the provided byte
     *
     * @param byteToAdd byte to be added for digest computation
     */
    public void update(byte byteToAdd) {
        messageDigest.update(byteToAdd);
    }

    /**
     * Updates the digest using the provided array of bytes
     *
     * @param bytes array of bytes
     */
    public void update(byte[] bytes) {
        if (bytes != null) {
            messageDigest.update(bytes);
        }
    }

    /**
     * Updates the digest by reading the provided {@code InputStream}.
     * NOTE: the method consumes the {@code InputStream}, and closes it after.
     *
     * @param inputStream {@link InputStream}
     * @throws IOException if an error is thrown on InputStream reading
     */
    public void update(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            return;
        }
        try (InputStream is = inputStream) {
            int count;
            byte[] buffer = new byte[4096];
            while ((count = is.read(buffer)) >= 0) {
                messageDigest.update(buffer, 0, count);
            }
        }
    }

    /**
     * Returns the {@code DSSMessageDigest} accordingly to the current state.
     * This method resets the state of message-digest.
     *
     * @return {@link DSSMessageDigest}
     */
    public DSSMessageDigest getMessageDigest() {
        return new DSSMessageDigest(digestAlgorithm, messageDigest.digest());
    }

}
