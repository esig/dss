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
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIdPkixOcspNoCheck;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrusted;
import eu.europa.esig.dss.diagnostic.jaxb.XmlValAssuredShortTermCertificate;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationDataRequiredCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RevocationDataRequiredCheckTest extends AbstractTestCheck {

    @Test
    void trustedCertTest() {
        XmlCertificate xc = new XmlCertificate();
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        xc.setTrusted(xmlTrusted);

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void selfSignedCertTest() {
        XmlCertificate xc = new XmlCertificate();
        xc.setSelfSigned(true);

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void ocspNoCheckValidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlIdPkixOcspNoCheck extension = new XmlIdPkixOcspNoCheck();
        extension.setOID("1.3.6.1.5.5.7.48.1.5");
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void shortTermValidityAssuredValidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlValAssuredShortTermCertificate extension = new XmlValAssuredShortTermCertificate();
        extension.setOID("0.4.0.194121.2.1");
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void customExtensionValidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension extension = new XmlCertificateExtension();
        extension.setOID("1.58.512.125");
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.58.512.125");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void customExtensionAcceptAllValidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension extension = new XmlCertificateExtension();
        extension.setOID("1.58.512.125");
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("*");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void certPolicyValidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificatePolicies extension = new XmlCertificatePolicies();
        extension.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.15.45.145");
        extension.getCertificatePolicy().add(certificatePolicy);

        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void certPolicyAcceptAllValidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificatePolicies extension = new XmlCertificatePolicies();
        extension.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.15.45.145");
        extension.getCertificatePolicy().add(certificatePolicy);

        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("*");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsAllMatchTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlIdPkixOcspNoCheck extensionOne = new XmlIdPkixOcspNoCheck();
        extensionOne.setOID("1.3.6.1.5.5.7.48.1.5");

        XmlValAssuredShortTermCertificate extensionTwo = new XmlValAssuredShortTermCertificate();
        extensionTwo.setOID("0.4.0.194121.2.1");

        XmlCertificatePolicies extensionThree = new XmlCertificatePolicies();
        extensionThree.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.15.45.145");
        extensionThree.getCertificatePolicy().add(certificatePolicy);

        xc.setCertificateExtensions(Arrays.asList(extensionTwo, extensionOne, extensionThree));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsWithShortTermCertTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlValAssuredShortTermCertificate extension = new XmlValAssuredShortTermCertificate();
        extension.setOID("0.4.0.194121.2.1");
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsWithPolicyTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificatePolicies extension = new XmlCertificatePolicies();
        extension.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.15.45.145");
        extension.getCertificatePolicy().add(certificatePolicy);
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsWithShortTermCertAndInvalidPolicyTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlValAssuredShortTermCertificate extensionOne = new XmlValAssuredShortTermCertificate();
        extensionOne.setOID("0.4.0.194121.2.1");

        XmlCertificatePolicies extensionTwo = new XmlCertificatePolicies();
        extensionTwo.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.142.42.54");
        extensionTwo.getCertificatePolicy().add(certificatePolicy);

        xc.setCertificateExtensions(Arrays.asList(extensionOne, extensionTwo));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsWithShortTermCertAndInvalidCertExtensionTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension extensionOne = new XmlCertificateExtension();
        extensionOne.setOID("0.15.453.12");

        XmlCertificatePolicies extensionTwo = new XmlCertificatePolicies();
        extensionTwo.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.15.45.145");
        extensionTwo.getCertificatePolicy().add(certificatePolicy);

        xc.setCertificateExtensions(Arrays.asList(extensionOne, extensionTwo));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsAllInvalidTrustedTest() {
        XmlCertificate xc = new XmlCertificate();
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        xc.setTrusted(xmlTrusted);

        XmlCertificateExtension extensionOne = new XmlCertificateExtension();
        extensionOne.setOID("0.15.453.12");

        XmlCertificatePolicies extensionTwo = new XmlCertificatePolicies();
        extensionTwo.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.153.15.12");
        extensionTwo.getCertificatePolicy().add(certificatePolicy);

        xc.setCertificateExtensions(Arrays.asList(extensionOne, extensionTwo));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsAllInvalidSelfSignedTest() {
        XmlCertificate xc = new XmlCertificate();
        xc.setSelfSigned(true);

        XmlCertificateExtension extensionOne = new XmlCertificateExtension();
        extensionOne.setOID("0.15.453.12");

        XmlCertificatePolicies extensionTwo = new XmlCertificatePolicies();
        extensionTwo.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.153.15.12");
        extensionTwo.getCertificatePolicy().add(certificatePolicy);

        xc.setCertificateExtensions(Arrays.asList(extensionOne, extensionTwo));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void nothingInvalidTest() {
        XmlCertificate xc = new XmlCertificate();

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void ocspNoCheckInvalidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlIdPkixOcspNoCheck extension = new XmlIdPkixOcspNoCheck();
        extension.setOID("1.3.6.1.5.5.7.48.1.5");
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void customExtensionInvalidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension extension = new XmlCertificateExtension();
        extension.setOID("1.58.512.125");
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void noExtensionAcceptAllInvalidTest() {
        XmlCertificate xc = new XmlCertificate();

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("*");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void certPolicyInvalidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificatePolicies extension = new XmlCertificatePolicies();
        extension.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.15.45.145");
        extension.getCertificatePolicy().add(certificatePolicy);

        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.11.15.52");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void noCertPolicyAcceptAllValidTest() {
        XmlCertificate xc = new XmlCertificate();

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("*");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsPolicyInvalidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificatePolicies extension = new XmlCertificatePolicies();
        extension.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.15.45.145");
        extension.getCertificatePolicy().add(certificatePolicy);
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.48.75.1");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsExtensionInvalidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension extension = new XmlCertificateExtension();
        extension.setOID("0.1.5.45.25");
        xc.setCertificateExtensions(Collections.singletonList(extension));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void allConstraintsAllInvalidTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension extensionOne = new XmlCertificateExtension();
        extensionOne.setOID("0.15.453.12");

        XmlCertificatePolicies extensionTwo = new XmlCertificatePolicies();
        extensionTwo.setOID("2.5.29.32");

        XmlCertificatePolicy certificatePolicy = new XmlCertificatePolicy();
        certificatePolicy.setValue("1.153.15.12");
        extensionTwo.getCertificatePolicy().add(certificatePolicy);

        xc.setCertificateExtensions(Arrays.asList(extensionOne, extensionTwo));

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.FAIL);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("1.3.6.1.5.5.7.48.1.5");
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);

        MultiValuesConstraint certPoliciesConstraint = new MultiValuesConstraint();
        certPoliciesConstraint.getId().add("1.15.45.145");
        constraint.setCertificatePolicies(certPoliciesConstraint);

        XmlSubXCV result = new XmlSubXCV();
        RevocationDataRequiredCheck<?> rdsc = new RevocationDataRequiredCheck<>(i18nProvider, result, new CertificateWrapper(xc), new Date(), null, constraint);
        rdsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
