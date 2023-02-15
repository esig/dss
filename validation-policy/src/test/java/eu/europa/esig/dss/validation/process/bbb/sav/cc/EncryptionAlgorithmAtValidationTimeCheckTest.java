package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
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

public class EncryptionAlgorithmAtValidationTimeCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
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
    public void invalid() {
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
    public void dateNotDefinedTest() {
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
    public void notDefinedKeySizeTest() {
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
    public void dateNotDefinedInvalidTest() {
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
    public void algoNotDefinedTest() {
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
    public void overwrittenLevelTest() {
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
    public void noGlobalLevelTest() {
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
    public void noLevelTest() {
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
    public void afterUpdateDateTest() {
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
    public void noUpdateDateTest() {
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
    public void noLevelAfterUpdateTest() {
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
