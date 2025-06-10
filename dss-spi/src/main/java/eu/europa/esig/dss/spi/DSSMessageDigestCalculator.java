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
package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * This class is used to compute {@code DSSMessageDigest} based on the provided input
 *
 */
public class DSSMessageDigestCalculator {

    private static final Logger LOG = LoggerFactory.getLogger(DSSMessageDigestCalculator.class);

    /** The Map of DigestAlgorithm and corresponding computed message-digest */
    private final Map<DigestAlgorithm, MessageDigest> messageDigestMap;

    /**
     * Default constructor with a single digest algorithm
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for message-digest computation
     */
    public DSSMessageDigestCalculator(DigestAlgorithm digestAlgorithm) {
        this(Collections.singletonList(digestAlgorithm));
    }

    /**
     * Constructor with multiple digest algorithms
     *
     * @param digestAlgorithms {@link DigestAlgorithm} to be used for message-digest computation
     */
    public DSSMessageDigestCalculator(Collection<DigestAlgorithm> digestAlgorithms) {
        this.messageDigestMap = toMessageDigestMap(digestAlgorithms);
    }

    private Map<DigestAlgorithm, MessageDigest> toMessageDigestMap(Collection<DigestAlgorithm> digestAlgorithms) {
        Objects.requireNonNull(digestAlgorithms, "DigestAlgorithms shall be defined!");
        if (Utils.isCollectionEmpty(digestAlgorithms)) {
            throw new IllegalArgumentException("DigestAlgorithms collection cannot be empty!");
        }
        final Map<DigestAlgorithm, MessageDigest> messageDigestList = new EnumMap<>(DigestAlgorithm.class);
        for (DigestAlgorithm digestAlgorithm : digestAlgorithms) {
            Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
            messageDigestList.put(digestAlgorithm, toMessageDigest(digestAlgorithm));
        }
        return messageDigestList;
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
        for (MessageDigest md : getMessageDigests()) {
            md.update(byteToAdd);
        }
    }

    /**
     * Updates the digest using the provided array of bytes
     *
     * @param bytes array of bytes
     */
    public void update(byte[] bytes) {
        if (bytes != null) {
            for (MessageDigest md : getMessageDigests()) {
                md.update(bytes);
            }
        }
    }

    /**
     * Updates the bytes starting from the offset and a specified length
     *
     * @param bytes array of bytes
     * @param offset to start bytes update from
     * @param length the length of bytes array to be updated
     */
    public void update(byte[] bytes, int offset, int length) {
        if (bytes != null) {
            for (MessageDigest md : getMessageDigests()) {
                md.update(bytes, offset, length);
            }
        }
    }

    private Collection<MessageDigest> getMessageDigests() {
        return messageDigestMap.values();
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
                update(buffer, 0, count);
            }
        }
    }

    /**
     * Returns the {@code DSSMessageDigest} accordingly to the current state.
     * This method resets the state of message-digest.
     *
     * @return {@link DSSMessageDigest}
     * @deprecated since DSS 6.3. Please use {@code #getMessageDigest(DigestAlgorithm)} method instead.
     */
    @Deprecated
    public DSSMessageDigest getMessageDigest() {
        LOG.warn("Use of deprecated method #getMessageDigest()! Please use #getMessageDigest(DigestAlgorithm) method instead!");
        return getMessageDigest(messageDigestMap.keySet().iterator().next());
    }

    /**
     * Returns the {@code DSSMessageDigest} accordingly to the given {@code digestAlgorithm}
     * This method resets the state of message-digest.
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to get a corresponding {@code DSSMessageDigest} for
     * @return {@link DSSMessageDigest}
     */
    public DSSMessageDigest getMessageDigest(DigestAlgorithm digestAlgorithm) {
        MessageDigest messageDigest = messageDigestMap.get(digestAlgorithm);
        if (messageDigest == null) {
            throw new IllegalArgumentException("The DigestAlgorithm was not used on message-digest computation!");
        }
        return new DSSMessageDigest(digestAlgorithm, messageDigest.digest());
    }

    /**
     * Gets OutputStream that can be used to calculate digest on the fly.
     * This method will update the digest within the current instance of {@code DSSMessageDigestCalculator},
     * when the returned {@code OutputStream} is being updated.
     *
     * @return {@link OutputStream}
     */
    public OutputStream getOutputStream() {
        return getOutputStream(Utils.nullOutputStream());
    }

    /**
     * Gets OutputStream that can be used to calculate digest on the fly.
     * This method will write the binaries into the provided {@code outputStream} as well
     * as will update the digest within the current instance of {@code DSSMessageDigestCalculator}
     *
     * @param outputStream to be embedded into
     * @return {@link OutputStream}
     */
    public OutputStream getOutputStream(OutputStream outputStream) {
        return new OutputStream() {

            /** Provided OutputStream */
            private final OutputStream wrappedOS = outputStream;

            @Override
            public void write(int b) throws IOException {
                wrappedOS.write(b);
                update((byte) b);
            }

            @Override
            public void write(byte[] b) throws IOException {
                wrappedOS.write(b);
                update(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                wrappedOS.write(b, off, len);
                update(b, off, len);
            }

            @Override
            public void close() throws IOException {
                wrappedOS.close();
                super.close();
            }

        };
    }

}
