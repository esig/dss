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

import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ByteRangeInputStreamTest {

    @Test
    void simpleByteRangeTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 0, 4, 10, 5 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("0123abcde", new String(result));
        }
    }

    @Test
    void noBeginningByteRangeTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 0, 0, 10, 5 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("abcde", new String(result));
        }
    }

    @Test
    void noEndByteRangeTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 0, 4, 10, 0 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("0123", new String(result));
        }
    }

    @Test
    void emptyByteRangeTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 0, 0, 100, 0 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("", new String(result));
        }
    }

    @Test
    void outOfRangeByteRangeTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 0, 100, 1200, 100 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("0123456789abcdefghijklmnopqrstuvwxyz", new String(result));
        }
    }

    @Test
    void outOfRangeSecondByteRangeTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 0, 2, 1200, 100 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("01", new String(result));
        }
    }

    @Test
    void doubleByteRangeInputStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange firstByteRange = new ByteRange(new int[] { 0, 4, 10, 5 });
        ByteRange secondByteRange = new ByteRange(new int[] { 0, 2, 4, 2 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream firstBris = new ByteRangeInputStream(is, firstByteRange);
            ByteRangeInputStream secondBris = new ByteRangeInputStream(firstBris, secondByteRange)) {
            byte[] result = Utils.toByteArray(secondBris);
            assertEquals("01ab", new String(result));
        }
    }

    @Test
    void shiftedRangeInputStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 2, 2, 10, 2 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("23ab", new String(result));
        }
    }

    @Test
    void shiftedRangeSkipSecondInputStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 3, 2, 6, 0 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("34", new String(result));
        }
    }

    @Test
    void doubleByteRangeSkipFirstInputStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange firstByteRange = new ByteRange(new int[] { 2, 4, 10, 5 });
        ByteRange secondByteRange = new ByteRange(new int[] { 0, 2, 4, 2 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream firstBris = new ByteRangeInputStream(is, firstByteRange);
             ByteRangeInputStream secondBris = new ByteRangeInputStream(firstBris, secondByteRange)) {
            byte[] result = Utils.toByteArray(secondBris);
            assertEquals("23ab", new String(result));
        }
    }

    @Test
    void doubleByteRangeMixedSecondStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange firstByteRange = new ByteRange(new int[] { 0, 4, 10, 5 });
        ByteRange secondByteRange = new ByteRange(new int[] { 3, 2, 6, 0 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream firstBris = new ByteRangeInputStream(is, firstByteRange);
             ByteRangeInputStream secondBris = new ByteRangeInputStream(firstBris, secondByteRange)) {
            byte[] result = Utils.toByteArray(secondBris);
            assertEquals("3a", new String(result));
        }
    }

    @Test
    void bigByteRangeStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 0, 10, 15, 5 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("0123456789fghij", new String(result));
        }
    }

    @Test
    void inclusiveFirstByteRangeStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange firstByteRange = new ByteRange(new int[] { 0, 10, 15, 5 });
        ByteRange secondByteRange = new ByteRange(new int[] { 0, 5, 8, 2 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream firstBris = new ByteRangeInputStream(is, firstByteRange);
             ByteRangeInputStream secondBris = new ByteRangeInputStream(firstBris, secondByteRange)) {
            byte[] result = Utils.toByteArray(secondBris);
            assertEquals("0123489", new String(result));
        }
    }

    @Test
    void inclusiveSecondByteRangeStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange firstByteRange = new ByteRange(new int[] { 5, 5, 15, 10 });
        ByteRange secondByteRange = new ByteRange(new int[] { 6, 2, 9, 1 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream firstBris = new ByteRangeInputStream(is, firstByteRange);
             ByteRangeInputStream secondBris = new ByteRangeInputStream(firstBris, secondByteRange)) {
            byte[] result = Utils.toByteArray(secondBris);
            assertEquals("ghj", new String(result));
        }
    }

    @Test
    void straightByteRangeStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange firstByteRange = new ByteRange(new int[] { 0, 5, 8, 2 });
        ByteRange secondByteRange = new ByteRange(new int[] { 2, 2, 6, 1 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream firstBris = new ByteRangeInputStream(is, firstByteRange);
             ByteRangeInputStream secondBris = new ByteRangeInputStream(firstBris, secondByteRange)) {
            byte[] result = Utils.toByteArray(secondBris);
            assertEquals("239", new String(result));
        }
    }

    @Test
    void opposedOrderByteRangeStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange firstByteRange = new ByteRange(new int[] { 2, 2, 8, 5 });
        ByteRange secondByteRange = new ByteRange(new int[] { 0, 4, 6, 1 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream firstBris = new ByteRangeInputStream(is, firstByteRange);
             ByteRangeInputStream secondBris = new ByteRangeInputStream(firstBris, secondByteRange)) {
            byte[] result = Utils.toByteArray(secondBris);
            assertEquals("2389c", new String(result));
        }
    }

    @Test
    void threeArraysByteRangeStreamTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange firstByteRange = new ByteRange(new int[] { 0, 10, 15, 5 });
        ByteRange secondByteRange = new ByteRange(new int[] { 0, 5, 8, 2 });
        ByteRange thirdByteRange = new ByteRange(new int[] { 2, 2, 6, 1 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream firstBris = new ByteRangeInputStream(is, firstByteRange);
             ByteRangeInputStream secondBris = new ByteRangeInputStream(firstBris, secondByteRange);
             ByteRangeInputStream thirdBris = new ByteRangeInputStream(secondBris, thirdByteRange)) {
            byte[] result = Utils.toByteArray(thirdBris);
            assertEquals("239", new String(result));
        }
    }

    @Test
    void zeroByteRangeTest() throws IOException {
        String str = "0123456789abcdefghijklmnopqrstuvwxyz";
        ByteRange byteRange = new ByteRange(new int[] { 0, 0, 0, 0 });
        try (InputStream is = new ByteArrayInputStream(str.getBytes());
             ByteRangeInputStream bris = new ByteRangeInputStream(is, byteRange)) {
            byte[] result = Utils.toByteArray(bris);
            assertEquals("", new String(result));
        }
    }

}
