/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.xades.signature.opendocument;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

public abstract class AbstractOpenDocumentSetTestSignature extends AbstractOpenDocumentTestSignature {

    protected DSSDocument fileToTest;

    protected static Stream<Arguments> data() {
        File folder = new File("src/test/resources/opendocument");
        Collection<File> listFiles = Utils.listFiles(folder,
                new String[] { "odt", "ods", "odp", "odg" }, true);

        List<Arguments> args = new ArrayList<>();
        for (File file : listFiles) {
            args.add(Arguments.of(new FileDocument(file)));
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Validation {index} : {0}")
    @MethodSource("data")
    public void test(DSSDocument fileToTest) {
        this.fileToTest = fileToTest;

        super.signAndVerify();
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return fileToTest;
    }

    @Override
    public void signAndVerify() {
    }

}
