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
package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.pades.signature.visible.suite.PAdESExistingSignatureFieldTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESFieldLevelBTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESMultipleVisibleSignaturesTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESNonLatinCharactersSignatureTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESSignatureFieldTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESTextWrappingTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESVisibleImageScalingTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESVisibleSigOutsidePageTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESVisibleSignWithSignatureFieldTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESVisibleSignatureTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESVisibleSignatureWithJavaFontTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESVisibleWithOverlappingFieldsTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESVisibleZoomRotationTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESWithSignatureAndTimestampVisibleTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESWithSignatureInvisibleAndTimestampVisibleTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESWithSignatureVisibleAndTimestampInvisibleTest;
import eu.europa.esig.dss.pades.signature.visible.suite.PDFSignatureServiceTest;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectClasses(value = { PAdESSignatureFieldTest.class, PAdESVisibleSignatureTest.class, PAdESFieldLevelBTest.class,
        PAdESWithSignatureAndTimestampVisibleTest.class, PAdESWithSignatureVisibleAndTimestampInvisibleTest.class,
        PAdESWithSignatureInvisibleAndTimestampVisibleTest.class, PAdESVisibleSignatureWithJavaFontTest.class,
        PAdESNonLatinCharactersSignatureTest.class, PAdESVisibleZoomRotationTest.class, PAdESVisibleSignWithSignatureFieldTest.class,
        PDFSignatureServiceTest.class, PAdESMultipleVisibleSignaturesTest.class, PAdESVisibleWithOverlappingFieldsTest.class,
        PAdESVisibleImageScalingTest.class, PAdESExistingSignatureFieldTest.class, PAdESTextWrappingTest.class,
        PAdESVisibleSigOutsidePageTest.class })
public class ITextPAdESVisibleSignatureSuiteTest {

}
