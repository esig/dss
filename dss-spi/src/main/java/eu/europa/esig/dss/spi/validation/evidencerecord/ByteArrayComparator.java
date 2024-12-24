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
package eu.europa.esig.dss.spi.validation.evidencerecord;

import java.io.Serializable;
import java.util.Comparator;

/**
 * Used to compare two byte arrays.
 * Inspired by {@code <a href="https://github.com/bcgit/bc-java/blob/main/pkix/src/main/java/org/bouncycastle/tsp/ers/ByteArrayComparator.java">BC ByteArrayComparator implementation</a>}
 */
public class ByteArrayComparator implements Comparator<byte[]>, Serializable {

    private static final long serialVersionUID = 100676696837205640L;

    /** Singleton instance */
    private static ByteArrayComparator instance;

    /**
     * Default constructor
     */
    private ByteArrayComparator() {
        // empty
    }

    /**
     * Returns singleton instance of {@code ByteArrayComparator}
     *
     * @return {@link ByteArrayComparator}
     */
    public static ByteArrayComparator getInstance() {
        if (instance == null) {
            instance = new ByteArrayComparator();
        }
        return instance;
    }

    @Override
    public int compare(byte[] o1, byte[] o2) {
        for (int i = 0; i < o1.length && i < o2.length; i++) {
            int a = (o1[i] & 0xff);
            int b = (o2[i] & 0xff);
            if (a < b) {
                return -1;
            } else if (a > b) {
                return 1;
            }
        }
        return o1.length - o2.length;
    }

}
