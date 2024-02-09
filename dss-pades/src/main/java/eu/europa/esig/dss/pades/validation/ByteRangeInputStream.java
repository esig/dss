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
package eu.europa.esig.dss.pades.validation;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Reads InputStream according to the given {@code ByteRange}
 *
 */
public class ByteRangeInputStream extends FilterInputStream {

    /** The ByteRange to be read */
    private final ByteRange byteRange;

    /** Internal variable identifying the current position of InputStream */
    private int position = 0;

    /**
     * Default constructor
     *
     * @param is {@link InputStream} wrapped InputStream to access a PDF document content
     * @param byteRange {@link ByteRange} to read
     */
    public ByteRangeInputStream(final InputStream is, final ByteRange byteRange) {
        super(is);
        Objects.requireNonNull(is, "InputStream cannot be null!");
        Objects.requireNonNull(byteRange, "ByteRange cannot be null!");
        this.byteRange = byteRange;
    }

    @Override
    public int read() throws IOException {
        ensureFirstByteRangePosition();

        int b = -1;
        if (position == byteRange.getFirstPartEnd()) {
            int offset =  byteRange.getSecondPartStart() - byteRange.getFirstPartEnd();
            skip(offset);
        } else if (position < byteRange.getFirstPartStart()) {
            int offset = byteRange.getFirstPartStart() - position;
            skip(offset);
        }
        if (isPositionWithinRange(position + 1)) {
            b = super.read();
            if (b != -1) {
                ++position;
            }
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        Objects.requireNonNull(b, "Byte array cannot be null!");

        ensureFirstByteRangePosition();

        int totalRead = 0;
        while (totalRead < len) {
            int remaining = len - totalRead;
            int toRead = remainingBytesInCurrentPart();
            if (toRead <= 0) {
                break;
            }

            int readBytes = super.read(b, off + totalRead, Math.min(remaining, toRead));
            if (readBytes < 1) {
                break;
            }
            totalRead += readBytes;
            position += readBytes;
        }

        if (totalRead < 1) {
            return -1;
        }

        return totalRead;
    }

    private long ensureFirstByteRangePosition() throws IOException {
        return skip(0);
    }

    @Override
    public long skip(long n) throws IOException {
        long finalPosition = position + n;
        long offset;
        if (finalPosition >= byteRange.getFirstPartStart() + byteRange.getFirstPartEnd() && finalPosition < byteRange.getSecondPartStart()) {
            offset = byteRange.getSecondPartStart() + n - byteRange.getFirstPartStart() - byteRange.getFirstPartEnd();
        } else if (position < byteRange.getFirstPartStart()) {
            offset = byteRange.getFirstPartStart() - position + n;
        } else {
            offset = n;
        }
        long skipped = super.skip(offset);
        if (skipped > offset) {
            skipped = offset;
        }
        position += (int) skipped;
        return skipped;
    }

    private boolean isPositionWithinRange(int position) {
        return isPositionWithinFirstPart(position) || isPositionWithinSecondPart(position);
    }

    private boolean isPositionWithinFirstPart(int position) {
        return position >= byteRange.getFirstPartStart() && position <= byteRange.getFirstPartStart() + byteRange.getFirstPartEnd();
    }

    private boolean isPositionWithinSecondPart(int position) {
        return position >= byteRange.getSecondPartStart() && position <= byteRange.getSecondPartStart() + byteRange.getSecondPartEnd();
    }

    private int remainingBytesInCurrentPart() {
        if (isPositionWithinFirstPart(position)) {
            return byteRange.getFirstPartStart() + byteRange.getFirstPartEnd() - position;
        } else if (isPositionWithinSecondPart(position)) {
            return byteRange.getSecondPartStart() + byteRange.getSecondPartEnd() - position;
        }
        return 0;
    }

}
