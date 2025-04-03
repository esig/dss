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
package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.CryptographicConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncryptionAlgorithmAtValidationTimeCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        rsa1900.setDate("2026");
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "2048", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        rsa1900.setDate("2026");
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "1024", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void dateNotDefinedTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "2048", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void notDefinedKeySizeTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "2048", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void dateNotDefinedInvalidTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "1024", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void algoNotDefinedTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.DSA, "256", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void overwrittenLevelTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setLevel(Level.WARN);
        algoExpirationDate.setFormat("yyyy");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        rsa1900.setDate("2026");
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "1024", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.WARNING, constraints.get(0).getStatus());
    }

    @Test
    void noGlobalLevelTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setLevel(Level.FAIL);
        algoExpirationDate.setFormat("yyyy");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        rsa1900.setDate("2026");
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "1024", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noLevelTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        rsa1900.setDate("2026");
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "1024", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(0, constraints.size());
    }

    @Test
    void afterUpdateDateTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");
        algoExpirationDate.setUpdateDate("2008");
        algoExpirationDate.setLevelAfterUpdate(Level.WARN);

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        rsa1900.setDate("2026");
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "1024", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.WARNING, constraints.get(0).getStatus());
    }

    @Test
    void noUpdateDateTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");
        algoExpirationDate.setLevelAfterUpdate(Level.WARN);

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        rsa1900.setDate("2026");
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "1024", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noLevelAfterUpdateTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");
        algoExpirationDate.setUpdateDate("2008");

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        rsa1000.setDate("2009");
        algoExpirationDate.getAlgos().add(rsa1000);

        Algo rsa1900 = new Algo();
        rsa1900.setValue("RSA");
        rsa1900.setSize(1900);
        rsa1900.setDate("2026");
        algoExpirationDate.getAlgos().add(rsa1900);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        EncryptionAlgorithmAtValidationTimeCheck eaovtc = new EncryptionAlgorithmAtValidationTimeCheck(i18nProvider, EncryptionAlgorithm.RSA, "1024", calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        eaovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
