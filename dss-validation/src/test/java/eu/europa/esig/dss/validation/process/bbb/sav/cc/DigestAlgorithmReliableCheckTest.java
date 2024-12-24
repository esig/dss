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
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DigestAlgorithmReliableCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
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
    void invalid() {
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
    void validDefinition() {
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
    void overwrittenLevelTest() {
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
    void noGlobalLevelTest() {
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
    void noLevelTest() {
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
