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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlInhibitAnyPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyConstraints;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicyTreeCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificatePolicyTreeCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void noSignCertPolicy() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void otherSignCertPolicy() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void validCaExplicitPolicy() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidCaExplicitPolicy() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void validRootCertReqExplicitPolOnePolicy() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidRootCertReqExplicitPolOnePolicy() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void caNoPolicy() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void caAnyPolicy() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void caAnyPolicySelfSigned() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void caAnyPolicyWithInhibitAnyPolicyValid() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(1);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlInhibitAnyPolicy inhibitAnyPolicy = new XmlInhibitAnyPolicy();
        inhibitAnyPolicy.setOID(CertificateExtensionEnum.INHIBIT_ANY_POLICY.getOid());
        inhibitAnyPolicy.setValue(1);
        rootCertificate.getCertificateExtensions().add(inhibitAnyPolicy);

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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void caAnyPolicyWithInhibitAnyPolicyInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(1);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlInhibitAnyPolicy inhibitAnyPolicy = new XmlInhibitAnyPolicy();
        inhibitAnyPolicy.setOID(CertificateExtensionEnum.INHIBIT_ANY_POLICY.getOid());
        inhibitAnyPolicy.setValue(0);
        rootCertificate.getCertificateExtensions().add(inhibitAnyPolicy);

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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void caSelfSignedAnyPolicyWithInhibitAnyPolicyInvalid() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(1);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlInhibitAnyPolicy inhibitAnyPolicy = new XmlInhibitAnyPolicy();
        inhibitAnyPolicy.setOID(CertificateExtensionEnum.INHIBIT_ANY_POLICY.getOid());
        inhibitAnyPolicy.setValue(0);
        rootCertificate.getCertificateExtensions().add(inhibitAnyPolicy);

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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void largeRequireExplicitPolicy() {
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void requireExplicitPolicySignCertNoPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(2);
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void signCertOverwriteRequireExplicitPolicyNoPolicy() {
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

        policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(0);
        signCertificate.getCertificateExtensions().add(policyConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void signCertOverwriteRequireExplicitPolicyWithPolicyNoPolicyCA() {
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

        policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(0);
        signCertificate.getCertificateExtensions().add(policyConstraints);

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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void signCertOverwriteRequireExplicitPolicyWithPolicy() {
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

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();

        policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(0);
        signCertificate.getCertificateExtensions().add(policyConstraints);

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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void signCertAnyPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(2);
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
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("2.5.29.32.0");
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void signCertAnyPolicyWithInhibitAnyPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(2);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlInhibitAnyPolicy inhibitAnyPolicy = new XmlInhibitAnyPolicy();
        inhibitAnyPolicy.setOID(CertificateExtensionEnum.INHIBIT_ANY_POLICY.getOid());
        inhibitAnyPolicy.setValue(0);
        rootCertificate.getCertificateExtensions().add(inhibitAnyPolicy);

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
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("2.5.29.32.0");
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void signCertAnyPolicyWithCaInhibitAnyPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(2);
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
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlInhibitAnyPolicy inhibitAnyPolicy = new XmlInhibitAnyPolicy();
        inhibitAnyPolicy.setOID(CertificateExtensionEnum.INHIBIT_ANY_POLICY.getOid());
        inhibitAnyPolicy.setValue(0);
        caCertificate.getCertificateExtensions().add(inhibitAnyPolicy);

        XmlCertificate signCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("2.5.29.32.0");
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void signCertAnyPolicyWithCaAllowingAnyPolicy() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(2);
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
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlInhibitAnyPolicy inhibitAnyPolicy = new XmlInhibitAnyPolicy();
        inhibitAnyPolicy.setOID(CertificateExtensionEnum.INHIBIT_ANY_POLICY.getOid());
        inhibitAnyPolicy.setValue(1);
        caCertificate.getCertificateExtensions().add(inhibitAnyPolicy);

        XmlCertificate signCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("2.5.29.32.0");
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void multiPoliciesDescendingTest() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(2);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("11.22.33.44");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("111.222");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("11.22.33.44");
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void multiPoliciesDescendingInvalidTest() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(2);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("11.22.33.44");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("111.222");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("11.22.33.44");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("111.222");
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
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void multiPoliciesAscendingTest() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(2);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("11.22.33.44");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("11.22.33.44");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("111.222");
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void multiPoliciesAscendingInvalidTest() {
        XmlCertificate rootCertificate = new XmlCertificate();

        XmlPolicyConstraints policyConstraints = new XmlPolicyConstraints();
        policyConstraints.setOID(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
        policyConstraints.setRequireExplicitPolicy(2);
        rootCertificate.getCertificateExtensions().add(policyConstraints);

        XmlCertificatePolicies certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("111.222");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        rootCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate caCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("11.22.33.44");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        caCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlCertificate signCertificate = new XmlCertificate();

        certificatePolicies = new XmlCertificatePolicies();
        certificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.2.3.4.5");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("11.22.33.44");
        certificatePolicies.getCertificatePolicy().add(certificatePolicy);
        certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("111.222");
        signCertificate.getCertificateExtensions().add(certificatePolicies);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(caCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(rootCertificate);
        signCertificate.setCertificateChain(Arrays.asList(xmlChainItemOne, xmlChainItemTwo));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificatePolicyTreeCheck ptc = new CertificatePolicyTreeCheck(i18nProvider, result, new CertificateWrapper(signCertificate), constraint);
        ptc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
