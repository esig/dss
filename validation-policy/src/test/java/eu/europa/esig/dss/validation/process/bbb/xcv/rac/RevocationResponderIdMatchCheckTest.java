package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationResponderIdMatchCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RevocationResponderIdMatchCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setFoundCertificates(new XmlFoundCertificates());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(getXmlCertificate("C-Id-1"));
        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlRelatedCertificate responderIdRef = getXmlRelatedCertificate("C-Id-1");
        responderIdRef.getCertificateRefs().add(getSigningCertificateRef());
        xmlRevocation.getFoundCertificates().getRelatedCertificates().add(responderIdRef);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRAC result = new XmlRAC();
        RevocationResponderIdMatchCheck rrimc = new RevocationResponderIdMatchCheck(i18nProvider, result,
                new RevocationWrapper(xmlRevocation), constraint);
        rrimc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setFoundCertificates(new XmlFoundCertificates());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(getXmlCertificate("C-Id-1"));
        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlRelatedCertificate responderIdRef = getXmlRelatedCertificate("C-Id-2");
        responderIdRef.getCertificateRefs().add(getSigningCertificateRef());
        xmlRevocation.getFoundCertificates().getRelatedCertificates().add(responderIdRef);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRAC result = new XmlRAC();
        RevocationResponderIdMatchCheck rrimc = new RevocationResponderIdMatchCheck(i18nProvider, result,
                new RevocationWrapper(xmlRevocation), constraint);
        rrimc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void respIdNotPresent() {
        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setFoundCertificates(new XmlFoundCertificates());

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(getXmlCertificate("C-Id-1"));
        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRAC result = new XmlRAC();
        RevocationResponderIdMatchCheck rrimc = new RevocationResponderIdMatchCheck(i18nProvider, result,
                new RevocationWrapper(xmlRevocation), constraint);
        rrimc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void signCertNotPresent() {
        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setFoundCertificates(new XmlFoundCertificates());

        XmlRelatedCertificate responderIdRef = getXmlRelatedCertificate("C-Id-1");
        responderIdRef.getCertificateRefs().add(getSigningCertificateRef());
        xmlRevocation.getFoundCertificates().getRelatedCertificates().add(responderIdRef);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRAC result = new XmlRAC();
        RevocationResponderIdMatchCheck rrimc = new RevocationResponderIdMatchCheck(i18nProvider, result,
                new RevocationWrapper(xmlRevocation), constraint);
        rrimc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    private XmlCertificate getXmlCertificate(String id) {
        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setId(id);
        return xmlCertificate;
    }

    private XmlRelatedCertificate getXmlRelatedCertificate(String id) {
        XmlRelatedCertificate xmlRelatedCertificate = new XmlRelatedCertificate();
        xmlRelatedCertificate.setCertificate(getXmlCertificate(id));
        return xmlRelatedCertificate;
    }

    private XmlCertificateRef getSigningCertificateRef() {
        XmlCertificateRef xmlCertificateRef = new XmlCertificateRef();
        xmlCertificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        return xmlCertificateRef;
    }

}
