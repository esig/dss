package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
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

public class DigestAlgorithmReliableCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        ListAlgo listAlgo = new ListAlgo();

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        listAlgo.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        listAlgo.getAlgos().add(sha256);

        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        XmlCC result = new XmlCC();
        DigestAlgorithmReliableCheck darc = new DigestAlgorithmReliableCheck(i18nProvider, DigestAlgorithm.SHA256, result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        darc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        ListAlgo listAlgo = new ListAlgo();

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        listAlgo.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        listAlgo.getAlgos().add(sha256);

        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        XmlCC result = new XmlCC();
        DigestAlgorithmReliableCheck darc = new DigestAlgorithmReliableCheck(i18nProvider, DigestAlgorithm.MD2, result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        darc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void validDefinition() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();
        cryptographicConstraint.setLevel(Level.FAIL);

        ListAlgo listAlgo = new ListAlgo();

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        listAlgo.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        listAlgo.getAlgos().add(sha256);

        cryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);

        XmlCC result = new XmlCC();
        DigestAlgorithmReliableCheck darc = new DigestAlgorithmReliableCheck(i18nProvider, DigestAlgorithm.SHA256, result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        darc.execute();

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

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        listAlgo.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        listAlgo.getAlgos().add(sha256);

        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        XmlCC result = new XmlCC();
        DigestAlgorithmReliableCheck darc = new DigestAlgorithmReliableCheck(i18nProvider, DigestAlgorithm.MD2, result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        darc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.WARNING, constraints.get(0).getStatus());
    }

    @Test
    public void noGlobalLevelTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.setLevel(Level.FAIL);

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        listAlgo.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        listAlgo.getAlgos().add(sha256);

        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        XmlCC result = new XmlCC();
        DigestAlgorithmReliableCheck darc = new DigestAlgorithmReliableCheck(i18nProvider, DigestAlgorithm.MD2, result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        darc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void noLevelTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();

        Algo sha1 = new Algo();
        sha1.setValue("SHA1");
        listAlgo.getAlgos().add(sha1);

        Algo sha256 = new Algo();
        sha256.setValue("SHA256");
        listAlgo.getAlgos().add(sha256);

        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        XmlCC result = new XmlCC();
        DigestAlgorithmReliableCheck darc = new DigestAlgorithmReliableCheck(i18nProvider, DigestAlgorithm.MD2, result,
                ValidationProcessUtils.getCryptoPosition(Context.SIGNATURE), new CryptographicConstraintWrapper(cryptographicConstraint));
        darc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(0, constraints.size());
    }

}
