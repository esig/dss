package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.EllipticCurveKeySizeCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EllipticCurveKeySizeCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlBasicSignature basicSignature = new XmlBasicSignature();
        basicSignature.setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
        basicSignature.setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA256);
        basicSignature.setKeyLengthUsedToSignThisToken("256");

        xmlSignature.setBasicSignature(basicSignature);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        EllipticCurveKeySizeCheck ecksc = new EllipticCurveKeySizeCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ecksc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTest() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlBasicSignature basicSignature = new XmlBasicSignature();
        basicSignature.setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
        basicSignature.setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA256);
        basicSignature.setKeyLengthUsedToSignThisToken("384");

        xmlSignature.setBasicSignature(basicSignature);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        EllipticCurveKeySizeCheck ecksc = new EllipticCurveKeySizeCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ecksc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void notEcdsaTest() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlBasicSignature basicSignature = new XmlBasicSignature();
        basicSignature.setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.RSA);
        basicSignature.setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA256);
        basicSignature.setKeyLengthUsedToSignThisToken("384");

        xmlSignature.setBasicSignature(basicSignature);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        EllipticCurveKeySizeCheck ecksc = new EllipticCurveKeySizeCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ecksc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void notIdentifiedEncryptionAlgoTest() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlBasicSignature basicSignature = new XmlBasicSignature();
        basicSignature.setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA256);
        basicSignature.setKeyLengthUsedToSignThisToken("384");

        xmlSignature.setBasicSignature(basicSignature);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        EllipticCurveKeySizeCheck ecksc = new EllipticCurveKeySizeCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ecksc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void notIdentifiedDigestAlgoTest() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlBasicSignature basicSignature = new XmlBasicSignature();
        basicSignature.setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.RSA);
        basicSignature.setKeyLengthUsedToSignThisToken("384");

        xmlSignature.setBasicSignature(basicSignature);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        EllipticCurveKeySizeCheck ecksc = new EllipticCurveKeySizeCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ecksc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void notIdentifiedKeyLengthTest() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlBasicSignature basicSignature = new XmlBasicSignature();
        basicSignature.setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.RSA);
        basicSignature.setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA256);

        xmlSignature.setBasicSignature(basicSignature);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        EllipticCurveKeySizeCheck ecksc = new EllipticCurveKeySizeCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ecksc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void notAuthorizedDigestAlgoTest() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlBasicSignature basicSignature = new XmlBasicSignature();
        basicSignature.setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
        basicSignature.setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA1);
        basicSignature.setKeyLengthUsedToSignThisToken("256");

        xmlSignature.setBasicSignature(basicSignature);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        EllipticCurveKeySizeCheck ecksc = new EllipticCurveKeySizeCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ecksc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
