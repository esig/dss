package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralSubtree;
import eu.europa.esig.dss.diagnostic.jaxb.XmlNameConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectAlternativeNames;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.GeneralNameType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNameConstraintsCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateNameConstraintsCheckTest extends AbstractTestCheck {

    @Test
    public void permittedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Production Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesMissingAttribute() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesValidCANotPresentCertExt() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesInvalidCANotPresentCertExt() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Production Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesCADefinedValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesCADefinedInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree2,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesValidCAOverwrite() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Production Certificates,OU=permittedSubtree1");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesValidCARemoveProp() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,OU=permittedSubtree1");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesValidCAAddProp() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1,CN=Invalid");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void multiplePermittedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtreeOne = new XmlGeneralSubtree();
        xmlGeneralSubtreeOne.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeOne.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        XmlGeneralSubtree xmlGeneralSubtreeTwo = new XmlGeneralSubtree();
        xmlGeneralSubtreeTwo.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeTwo.setValue("C=US,O=Test Certificates,OU=permittedSubtree2");
        nameConstraints.getPermittedSubtrees().addAll(Arrays.asList(xmlGeneralSubtreeOne, xmlGeneralSubtreeTwo));
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree2,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void multiplePermittedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtreeOne = new XmlGeneralSubtree();
        xmlGeneralSubtreeOne.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeOne.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        XmlGeneralSubtree xmlGeneralSubtreeTwo = new XmlGeneralSubtree();
        xmlGeneralSubtreeTwo.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeTwo.setValue("C=US,O=Test Certificates,OU=permittedSubtree2");
        nameConstraints.getPermittedSubtrees().addAll(Arrays.asList(xmlGeneralSubtreeOne, xmlGeneralSubtreeTwo));
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree3,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void emptyPermittedSubtrees() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }
    @Test
    public void permittedSubtreesEmptyCertDN() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesMissingAttribute() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesValidCANotPresentCertExt() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Production Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesInvalidCANotPresentCertExt() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesCADefinedValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesCADefinedInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesValidCAAdd() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Production Certificates,OU=excludedSubtree1");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesValidCAAddProp() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1,CN=Invalid");
        nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void multipleExcludedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtreeOne = new XmlGeneralSubtree();
        xmlGeneralSubtreeOne.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeOne.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        XmlGeneralSubtree xmlGeneralSubtreeTwo = new XmlGeneralSubtree();
        xmlGeneralSubtreeTwo.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeTwo.setValue("C=US,O=Test Certificates,OU=excludedSubtree2");
        nameConstraints.getExcludedSubtrees().addAll(Arrays.asList(xmlGeneralSubtreeOne, xmlGeneralSubtreeTwo));
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree3,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void multipleExcludedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtreeOne = new XmlGeneralSubtree();
        xmlGeneralSubtreeOne.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeOne.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        XmlGeneralSubtree xmlGeneralSubtreeTwo = new XmlGeneralSubtree();
        xmlGeneralSubtreeTwo.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtreeTwo.setValue("C=US,O=Test Certificates,OU=excludedSubtree2");
        nameConstraints.getExcludedSubtrees().addAll(Arrays.asList(xmlGeneralSubtreeOne, xmlGeneralSubtreeTwo));
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree2,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void emptyExcludedSubtrees() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesEmptyCertDN() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedAndExcludedSubtreesValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);

        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedAndExcludedSubtreesInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);

        xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);

        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesSubAltNameValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        subjectAlternativeNames.getSubjectAlternativeName().add("CN=Valid DN nameConstraints EE Certificate Test2,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesSubAltNameInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        subjectAlternativeNames.getSubjectAlternativeName().add("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree2,O=Test Certificates,C=US");
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesSubAltNameValid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        subjectAlternativeNames.getSubjectAlternativeName().add("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree2,O=Test Certificates,C=US");
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesSubAltNameInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSubjectAlternativeNames subjectAlternativeNames = new XmlSubjectAlternativeNames();
        subjectAlternativeNames.setOID(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
        subjectAlternativeNames.getSubjectAlternativeName().add("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        subjectAlternativeNames.getSubjectAlternativeName().add("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getCertificateExtensions().add(subjectAlternativeNames);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesWithEscapedChar() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1\\,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesWithEscapedChar() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1\\,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesStartFromComma() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue(",CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void permittedSubtreesEndWithComma() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=permittedSubtree1");
        nameConstraints.getPermittedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US,");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesStartFromComma() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue(",CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void excludedSubtreesEndWithComma() {
        XmlCertificate rootCertificate = new XmlCertificate();
        rootCertificate.setSelfSigned(true);

        XmlNameConstraints nameConstraints = new XmlNameConstraints();
        nameConstraints.setOID(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());

        XmlGeneralSubtree xmlGeneralSubtree = new XmlGeneralSubtree();
        xmlGeneralSubtree.setType(GeneralNameType.DIRECTORY_NAME);
        xmlGeneralSubtree.setValue("C=US,O=Test Certificates,OU=excludedSubtree1");
        nameConstraints.getExcludedSubtrees().add(xmlGeneralSubtree);
        rootCertificate.getCertificateExtensions().add(nameConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(nameConstraints);

        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CON=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate signCertificate = new XmlCertificate();

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=excludedSubtree1,O=Test Certificates,C=US,");
        signCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateNameConstraintsCheck cncc = new CertificateNameConstraintsCheck(i18nProvider, result,
                new CertificateWrapper(signCertificate), constraint);
        cncc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
