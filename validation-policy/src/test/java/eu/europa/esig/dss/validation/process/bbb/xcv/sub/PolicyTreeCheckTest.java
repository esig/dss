package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyConstraints;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.PolicyTreeCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PolicyTreeCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(0);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void noSignCertPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(0);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void otherSignCertPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(0);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();
        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("6.7.8.9.0");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void validCaExplicitPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(0);
        caCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificate signCertificate = new XmlCertificate();
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidCaExplicitPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(0);
        caCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificate signCertificate = new XmlCertificate();
        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("6.7.8.9.0");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void validRootCertReqExplicitPolOnePolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(1);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidRootCertReqExplicitPolOnePolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(1);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();
        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("6.7.8.9.0");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void caNoPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(1);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlCertificate signCertificate = new XmlCertificate();
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void caAnyPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(1);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();
        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("2.5.29.32.0");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();
        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void caAnyPolicySelfSigned() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(1);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();
        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("2.5.29.32.0");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        caCertificate.setSelfSigned(true);

        XmlCertificate signCertificate = new XmlCertificate();
        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void largeRequireExplicitPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(3);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();

        XmlCertificate signCertificate = new XmlCertificate();

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        PolicyTreeCheck ptc = new PolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
