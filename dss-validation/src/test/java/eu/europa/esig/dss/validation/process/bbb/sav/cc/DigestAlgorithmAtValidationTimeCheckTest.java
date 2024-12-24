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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DigestAlgorithmAtValidationTimeCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        sha256.setDate("2029");
        algoExpirationDate.getAlgos().add(sha256);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA256, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidDate() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        sha256.setDate("2029");
        algoExpirationDate.getAlgos().add(sha256);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2032, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA256, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidAlgo() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        sha256.setDate("2029");
        algoExpirationDate.getAlgos().add(sha256);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA1, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notDefinedAlgoTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2022, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA256, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

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

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        sha256.setDate("2029");
        algoExpirationDate.getAlgos().add(sha256);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2032, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA256, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

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

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        sha256.setDate("2029");
        algoExpirationDate.getAlgos().add(sha256);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2032, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA256, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noLevelTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        sha256.setDate("2029");
        algoExpirationDate.getAlgos().add(sha256);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2032, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA256, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(0, constraints.size());
    }

    @Test
    void afterUpdateDateTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setFormat("yyyy");
        algoExpirationDate.setUpdateDate("2022");
        algoExpirationDate.setLevelAfterUpdate(Level.WARN);

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        sha256.setDate("2029");
        algoExpirationDate.getAlgos().add(sha256);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2032, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA256, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

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

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        sha256.setDate("2029");
        algoExpirationDate.getAlgos().add(sha256);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2032, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA256, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

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
        algoExpirationDate.setUpdateDate("2022");

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        sha1.setDate("2009");
        algoExpirationDate.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        sha256.setDate("2029");
        algoExpirationDate.getAlgos().add(sha256);

        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.set(2032, Calendar.JANUARY, 1);

        XmlCC result = new XmlCC();
        DigestAlgorithmAtValidationTimeCheck daovtc = new DigestAlgorithmAtValidationTimeCheck(i18nProvider, DigestAlgorithm.SHA256, calendar.getTime(),
                result, ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        daovtc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
