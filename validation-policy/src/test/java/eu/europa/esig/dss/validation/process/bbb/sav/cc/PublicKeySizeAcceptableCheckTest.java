package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PublicKeySizeAcceptableCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        ListAlgo listAlgo = new ListAlgo();

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        listAlgo.getAlgos().add(rsa1000);

        cryptographicConstraint.setMiniPublicKeySize(listAlgo);

        XmlCC result = new XmlCC();
        PublicKeySizeAcceptableCheck pkskc = new PublicKeySizeAcceptableCheck(i18nProvider, EncryptionAlgorithm.RSA, "2048", result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        pkskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        ListAlgo listAlgo = new ListAlgo();

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        listAlgo.getAlgos().add(rsa1000);

        cryptographicConstraint.setMiniPublicKeySize(listAlgo);

        XmlCC result = new XmlCC();
        PublicKeySizeAcceptableCheck pkskc = new PublicKeySizeAcceptableCheck(i18nProvider, EncryptionAlgorithm.RSA, "32", result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        pkskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidAlgo() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        ListAlgo listAlgo = new ListAlgo();

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        listAlgo.getAlgos().add(rsa1000);

        cryptographicConstraint.setMiniPublicKeySize(listAlgo);

        XmlCC result = new XmlCC();
        PublicKeySizeAcceptableCheck pkskc = new PublicKeySizeAcceptableCheck(i18nProvider, EncryptionAlgorithm.DSA, "1024", result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        pkskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void overwrittenLevelTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.setLevel(Level.WARN);

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        listAlgo.getAlgos().add(rsa1000);

        cryptographicConstraint.setMiniPublicKeySize(listAlgo);

        XmlCC result = new XmlCC();
        PublicKeySizeAcceptableCheck pkskc = new PublicKeySizeAcceptableCheck(i18nProvider, EncryptionAlgorithm.RSA, "32", result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        pkskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.WARNING, constraints.get(0).getStatus());
    }

    @Test
    public void noGlobalLevelTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.setLevel(Level.FAIL);

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        listAlgo.getAlgos().add(rsa1000);

        cryptographicConstraint.setMiniPublicKeySize(listAlgo);

        XmlCC result = new XmlCC();
        PublicKeySizeAcceptableCheck pkskc = new PublicKeySizeAcceptableCheck(i18nProvider, EncryptionAlgorithm.RSA, "32", result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        pkskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void noLevelTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();

        Algo rsa1000 = new Algo();
        rsa1000.setValue("RSA");
        rsa1000.setSize(1000);
        listAlgo.getAlgos().add(rsa1000);

        cryptographicConstraint.setMiniPublicKeySize(listAlgo);

        XmlCC result = new XmlCC();
        PublicKeySizeAcceptableCheck pkskc = new PublicKeySizeAcceptableCheck(i18nProvider, EncryptionAlgorithm.RSA, "32", result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        pkskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(0, constraints.size());
    }

}
