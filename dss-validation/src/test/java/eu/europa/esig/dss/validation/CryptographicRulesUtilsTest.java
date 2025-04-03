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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.dss.policy.CryptographicConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CryptographicRulesUtilsTest {

    @Test
    void isEncryptionAlgorithmReliableTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA));
        cryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertTrue(CryptographicRulesUtils.isEncryptionAlgorithmReliable(wrapper, EncryptionAlgorithm.RSA));
        assertFalse(CryptographicRulesUtils.isEncryptionAlgorithmReliable(wrapper, EncryptionAlgorithm.DSA));

        cryptographicConstraint.setAcceptableEncryptionAlgo(null);
        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertFalse(CryptographicRulesUtils.isEncryptionAlgorithmReliable(wrapper, EncryptionAlgorithm.RSA));
        assertFalse(CryptographicRulesUtils.isEncryptionAlgorithmReliable(wrapper, EncryptionAlgorithm.DSA));
    }

    @Test
    void isDigestAlgorithmReliableTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA256));
        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertTrue(CryptographicRulesUtils.isDigestAlgorithmReliable(wrapper, DigestAlgorithm.SHA256));
        assertFalse(CryptographicRulesUtils.isDigestAlgorithmReliable(wrapper, DigestAlgorithm.SHA1));

        cryptographicConstraint.setAcceptableDigestAlgo(null);
        cryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);

        wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertFalse(CryptographicRulesUtils.isDigestAlgorithmReliable(wrapper, DigestAlgorithm.SHA256));
        assertFalse(CryptographicRulesUtils.isDigestAlgorithmReliable(wrapper, DigestAlgorithm.SHA1));
    }

    @Test
    void isEncryptionAlgorithmWithKeySizeReliableTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 3000));
        cryptographicConstraint.setMiniPublicKeySize(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertTrue(CryptographicRulesUtils.isEncryptionAlgorithmWithKeySizeReliable(wrapper, EncryptionAlgorithm.RSA, 3072));
        assertFalse(CryptographicRulesUtils.isEncryptionAlgorithmWithKeySizeReliable(wrapper, EncryptionAlgorithm.RSA, 2048));

        // not defined -> reliable
        assertTrue(CryptographicRulesUtils.isEncryptionAlgorithmWithKeySizeReliable(wrapper, EncryptionAlgorithm.DSA, 3072));
        assertTrue(CryptographicRulesUtils.isEncryptionAlgorithmWithKeySizeReliable(wrapper, EncryptionAlgorithm.DSA, 2048));

        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.DSA, 2000));
        assertTrue(CryptographicRulesUtils.isEncryptionAlgorithmWithKeySizeReliable(wrapper, EncryptionAlgorithm.DSA, 3072));
        assertTrue(CryptographicRulesUtils.isEncryptionAlgorithmWithKeySizeReliable(wrapper, EncryptionAlgorithm.DSA, 2048));

        listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.DSA, 4000));
        cryptographicConstraint.setMiniPublicKeySize(listAlgo);
        assertFalse(CryptographicRulesUtils.isEncryptionAlgorithmWithKeySizeReliable(wrapper, EncryptionAlgorithm.DSA, 3072));
        assertFalse(CryptographicRulesUtils.isEncryptionAlgorithmWithKeySizeReliable(wrapper, EncryptionAlgorithm.DSA, 2048));
    }

    @Test
    void getReliableDigestAlgorithmsAtTimeTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA256));
        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);

        Calendar oldDateCalendar = Calendar.getInstance();
        oldDateCalendar.set(2010, Calendar.JANUARY, 1);

        Calendar newDateCalendar = Calendar.getInstance();
        newDateCalendar.set(2025, Calendar.JANUARY, 1);

        assertEquals(Collections.singletonList(DigestAlgorithm.SHA256), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(Collections.singletonList(DigestAlgorithm.SHA256), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, newDateCalendar.getTime()));

        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA512));

        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, newDateCalendar.getTime()));

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setLevel(Level.FAIL);
        algoExpirationDate.setFormat("yyyy");
        Algo algo = new Algo();
        algo.setValue("SHA256");
        algoExpirationDate.getAlgos().add(algo);
        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        // no expiration date
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, newDateCalendar.getTime()));

        algo.setDate("2029");
        // expiration in the future
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, newDateCalendar.getTime()));

        algo.setDate("2020");
        // expiration happened
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(Collections.singletonList(DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, newDateCalendar.getTime()));

        algo.setDate("2005");
        // old expiration
        assertEquals(Collections.singletonList(DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(Collections.singletonList(DigestAlgorithm.SHA512), CryptographicRulesUtils.getReliableDigestAlgorithmsAtTime(wrapper, newDateCalendar.getTime()));
    }

    @Test
    void getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTimeTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA));
        cryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);

        Calendar oldDateCalendar = Calendar.getInstance();
        oldDateCalendar.set(2010, Calendar.JANUARY, 1);

        Calendar newDateCalendar = Calendar.getInstance();
        newDateCalendar.set(2025, Calendar.JANUARY, 1);

        List<EncryptionAlgorithmWithMinKeySize> expectedList = new ArrayList<>();
        expectedList.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 0));

        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));

        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.ECDSA));
        expectedList.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0));

        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setLevel(Level.FAIL);
        algoExpirationDate.setFormat("yyyy");
        Algo algo = new Algo();
        algo.setValue("RSA");
        algo.setSize(1024);
        algoExpirationDate.getAlgos().add(algo);
        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        expectedList.clear();
        expectedList.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 1024));
        expectedList.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0));

        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));

        ListAlgo minKeySize = new ListAlgo();
        minKeySize.setLevel(Level.FAIL);
        minKeySize.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 1024));
        cryptographicConstraint.setMiniPublicKeySize(minKeySize);

        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));

        algo.setDate("2029");
        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));

        List<EncryptionAlgorithmWithMinKeySize> ecdsaOnlyList = new ArrayList<>();
        ecdsaOnlyList.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0));

        algo.setDate("2020");
        assertEquals(expectedList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(ecdsaOnlyList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));

        algo.setDate("2005");
        assertEquals(ecdsaOnlyList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(ecdsaOnlyList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));

        Algo biggerAlgo = new Algo();
        biggerAlgo.setValue("RSA");
        biggerAlgo.setSize(1900);
        biggerAlgo.setDate("2020");
        algoExpirationDate.getAlgos().add(biggerAlgo);

        List<EncryptionAlgorithmWithMinKeySize> rsa1900List = new ArrayList<>();
        rsa1900List.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 1900));
        rsa1900List.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0));

        assertEquals(rsa1900List, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(ecdsaOnlyList, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));

        biggerAlgo = new Algo();
        biggerAlgo.setValue("RSA");
        biggerAlgo.setSize(3000);
        biggerAlgo.setDate("2029");
        algoExpirationDate.getAlgos().add(biggerAlgo);

        List<EncryptionAlgorithmWithMinKeySize> rsa3000List = new ArrayList<>();
        rsa3000List.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 3000));
        rsa3000List.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0));

        assertEquals(rsa1900List, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(rsa3000List, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));

        minKeySize.getAlgos().clear();
        minKeySize.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 4000));

        List<EncryptionAlgorithmWithMinKeySize> rsa4000List = new ArrayList<>();
        rsa4000List.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 4000));
        rsa4000List.add(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0));

        assertEquals(rsa4000List, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, oldDateCalendar.getTime()));
        assertEquals(rsa4000List, CryptographicRulesUtils.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(wrapper, newDateCalendar.getTime()));
    }

    @Test
    void getExpirationDateEncryptionAlgoTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        AlgoExpirationDate listAlgo = new AlgoExpirationDate();
        listAlgo.setFormat("yyyy");
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 1900, "2022"));
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 3000, "2025"));
        cryptographicConstraint.setAlgoExpirationDate(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy");

        assertNull(CryptographicRulesUtils.getExpirationDate(wrapper, EncryptionAlgorithm.RSA, 1024));
        assertEquals(getDate("2022", simpleDateFormat), CryptographicRulesUtils.getExpirationDate(wrapper, EncryptionAlgorithm.RSA, 2048));
        assertEquals(getDate("2025", simpleDateFormat), CryptographicRulesUtils.getExpirationDate(wrapper, EncryptionAlgorithm.RSA, 3072));
        assertEquals(getDate("2025", simpleDateFormat), CryptographicRulesUtils.getExpirationDate(wrapper, EncryptionAlgorithm.RSA, 4096));
        assertNull(CryptographicRulesUtils.getExpirationDate(wrapper, EncryptionAlgorithm.DSA, 1024));
        assertNull(CryptographicRulesUtils.getExpirationDate(wrapper, EncryptionAlgorithm.DSA, 2048));
        assertNull(CryptographicRulesUtils.getExpirationDate(wrapper, EncryptionAlgorithm.DSA, 3072));
        assertNull(CryptographicRulesUtils.getExpirationDate(wrapper, EncryptionAlgorithm.DSA, 4096));
    }

    @Test
    void getExpirationDateDigestAlgoTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        AlgoExpirationDate listAlgo = new AlgoExpirationDate();
        listAlgo.setFormat("yyyy");
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA1, "2022"));
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA256, "2025"));
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA512, "2028"));
        cryptographicConstraint.setAlgoExpirationDate(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy");

        assertNull(CryptographicRulesUtils.getExpirationDate(wrapper, DigestAlgorithm.MD5));
        assertEquals(getDate("2022", simpleDateFormat), CryptographicRulesUtils.getExpirationDate(wrapper, DigestAlgorithm.SHA1));
        assertEquals(getDate("2025", simpleDateFormat), CryptographicRulesUtils.getExpirationDate(wrapper, DigestAlgorithm.SHA256));
        assertEquals(getDate("2028", simpleDateFormat), CryptographicRulesUtils.getExpirationDate(wrapper, DigestAlgorithm.SHA512));
        assertNull(CryptographicRulesUtils.getExpirationDate(wrapper, DigestAlgorithm.SHA224));
    }

    private Algo createAlgo(EncryptionAlgorithm encryptionAlgorithm) {
        return createAlgo(encryptionAlgorithm, null);
    }

    private Algo createAlgo(EncryptionAlgorithm encryptionAlgorithm, Integer length) {
        return createAlgo(encryptionAlgorithm, length, null);
    }

    private Algo createAlgo(EncryptionAlgorithm encryptionAlgorithm, Integer length, String expirationDate) {
        Algo algo = new Algo();
        algo.setValue(encryptionAlgorithm.getName());
        algo.setSize(length);
        algo.setDate(expirationDate);
        return algo;
    }

    private Algo createAlgo(DigestAlgorithm digestAlgorithm) {
        return createAlgo(digestAlgorithm, null);
    }

    private Algo createAlgo(DigestAlgorithm digestAlgorithm, String expirationDate) {
        Algo algo = new Algo();
        algo.setValue(digestAlgorithm.getName());
        algo.setDate(expirationDate);
        return algo;
    }

    private Date getDate(String dateString, SimpleDateFormat format) {
        if (dateString != null) {
            try {
                return format.parse(dateString);
            } catch (ParseException e) {
                fail(e);
            }
        }
        return null;
    }

}
