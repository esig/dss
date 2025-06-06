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
package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class CryptographicConstraintWrapperTest {

    @Test
    void levelsTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        CryptographicConstraintWrapper cryptographicSuite = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertNull(cryptographicSuite.getCryptographicSuiteUpdateDate());

        cryptographicConstraint.setAcceptableDigestAlgo(new ListAlgo());
        cryptographicConstraint.setAcceptableEncryptionAlgo(new ListAlgo());
        cryptographicConstraint.setMiniPublicKeySize(new ListAlgo());
        cryptographicConstraint.setAlgoExpirationDate(new AlgoExpirationDate());

        assertNull(cryptographicSuite.getLevel());
        assertNull(cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertNull(cryptographicSuite.getAcceptableEncryptionAlgorithmsLevel());
        assertNull(cryptographicSuite.getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertNull(cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertNull(cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setLevel(Level.FAIL);

        assertEquals(Level.FAIL, cryptographicSuite.getLevel()); // default
        // inherited from default
        assertEquals(Level.FAIL, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level.WARN);
        assertEquals(Level.WARN, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setLevel(Level.IGNORE);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAcceptableDigestAlgorithmsLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAcceptableEncryptionAlgorithmsLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAcceptableEncryptionAlgorithmsMiniKeySizeLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAlgorithmsExpirationDateLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());
    }

}
