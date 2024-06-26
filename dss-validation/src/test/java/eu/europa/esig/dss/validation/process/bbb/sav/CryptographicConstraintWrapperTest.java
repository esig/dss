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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CryptographicConstraintWrapperTest {

    @Test
    public void isEncryptionAlgorithmReliableTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA));
        cryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertTrue(wrapper.isEncryptionAlgorithmReliable(EncryptionAlgorithm.RSA));
        assertFalse(wrapper.isEncryptionAlgorithmReliable(EncryptionAlgorithm.DSA));

        cryptographicConstraint.setAcceptableEncryptionAlgo(null);
        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertFalse(wrapper.isEncryptionAlgorithmReliable(EncryptionAlgorithm.RSA));
        assertFalse(wrapper.isEncryptionAlgorithmReliable(EncryptionAlgorithm.DSA));
    }

    @Test
    public void isDigestAlgorithmReliableTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA256));
        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertTrue(wrapper.isDigestAlgorithmReliable(DigestAlgorithm.SHA256));
        assertFalse(wrapper.isDigestAlgorithmReliable(DigestAlgorithm.SHA1));

        cryptographicConstraint.setAcceptableDigestAlgo(null);
        cryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);

        wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertFalse(wrapper.isDigestAlgorithmReliable(DigestAlgorithm.SHA256));
        assertFalse(wrapper.isDigestAlgorithmReliable(DigestAlgorithm.SHA1));
    }

    @Test
    public void isEncryptionAlgorithmWithKeySizeReliableTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 3000));
        cryptographicConstraint.setMiniPublicKeySize(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertTrue(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.RSA, 3072));
        assertFalse(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.RSA, 2048));
        assertFalse(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.DSA, 3072));
        assertFalse(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.DSA, 2048));
    }

    @Test
    public void getExpirationDateEncryptionAlgoTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        AlgoExpirationDate listAlgo = new AlgoExpirationDate();
        listAlgo.setFormat("yyyy");
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 1900, "2022"));
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 3000, "2025"));
        cryptographicConstraint.setAlgoExpirationDate(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy");

        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.RSA, 1024));
        assertEquals(getDate("2022", simpleDateFormat), wrapper.getExpirationDate(EncryptionAlgorithm.RSA, 2048));
        assertEquals(getDate("2025", simpleDateFormat), wrapper.getExpirationDate(EncryptionAlgorithm.RSA, 3072));
        assertEquals(getDate("2025", simpleDateFormat), wrapper.getExpirationDate(EncryptionAlgorithm.RSA, 4096));
        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.DSA, 1024));
        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.DSA, 2048));
        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.DSA, 3072));
        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.DSA, 4096));
    }

    @Test
    public void getExpirationDateDigestAlgoTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        AlgoExpirationDate listAlgo = new AlgoExpirationDate();
        listAlgo.setFormat("yyyy");
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA1, "2022"));
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA256, "2025"));
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA512, "2028"));
        cryptographicConstraint.setAlgoExpirationDate(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy");

        assertNull(wrapper.getExpirationDate(DigestAlgorithm.MD5));
        assertEquals(getDate("2022", simpleDateFormat), wrapper.getExpirationDate(DigestAlgorithm.SHA1));
        assertEquals(getDate("2025", simpleDateFormat), wrapper.getExpirationDate(DigestAlgorithm.SHA256));
        assertEquals(getDate("2028", simpleDateFormat), wrapper.getExpirationDate(DigestAlgorithm.SHA512));
        assertNull(wrapper.getExpirationDate(DigestAlgorithm.SHA224));
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
