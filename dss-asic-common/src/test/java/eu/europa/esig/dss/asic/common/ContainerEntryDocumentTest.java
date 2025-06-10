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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContainerEntryDocumentTest {

    private DSSDocument containerEntry;

    @BeforeEach
    void init() {
        containerEntry = new InMemoryDocument("Hello world".getBytes(), "helloworld");
    }

    @Test
    void persistenceTest() {
        final Set<DSSDocument> hashSet = new HashSet<>();

        DSSDocument document = getPersistenceTestDocument();
        hashSet.add(document);
        assertTrue(hashSet.contains(document));

        Digest digest = document.getDigest(DigestAlgorithm.SHA256);
        assertNotNull(digest);

        assertTrue(hashSet.contains(document));
        assertTrue(hashSet.contains(getPersistenceTestDocument()));

        for (DSSDocument altDocument : getPersistenceTestAlternativeDocuments()) {
            assertFalse(hashSet.contains(altDocument), altDocument.toString());
        }
    }

    private DSSDocument getPersistenceTestDocument() {
        return new ContainerEntryDocument(containerEntry, new DSSZipEntry("helloworld"));
    }

    private List<DSSDocument> getPersistenceTestAlternativeDocuments() {
        DSSZipEntry diffZipEntry = new DSSZipEntry("helloworld");
        diffZipEntry.setCreationTime(new Date());
        return Arrays.asList(
                new ContainerEntryDocument(containerEntry, diffZipEntry),
                new ContainerEntryDocument(new InMemoryDocument("Hello world".getBytes(), "test.text"), new DSSZipEntry("test.text")),
                new ContainerEntryDocument(new InMemoryDocument("Bye world".getBytes(), "byeworld"), new DSSZipEntry("byeworld"))
        );
    }

}
