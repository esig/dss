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
package eu.europa.esig.dss.pades.signature;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses(value = { DigestStability.class, GetOriginalDocument.class, PAdESBExtendToLTACheckTimeStampID.class, PAdESDoubleSignature.class,
		PAdESLevelB.class, PAdESLevelBExternalSignature.class, PAdESLevelBLoop.class, PAdESLevelBNotEnoughSpaceForSignature.class,
		PAdESLevelBOnlySigningCert.class, PAdESLevelBWithContentTimestamp.class, PAdESLevelBWithDSA.class, PAdESLevelBWithECDSA.class,
		PAdESLevelBWithMoreThanOneSecondDelay.class, PAdESLevelBWithSHA256andMGF1.class, PAdESLevelImpossibleLTAException.class,
		PAdESLevelImpossibleLTException.class, PAdESLevelLT.class, PAdESLevelLTA.class, PAdESLevelLTWrongAIA.class, PAdESLevelT.class,
		PAdESLTACheckTimeStampedTimestampID.class, PAdESLTACheckTimeStampID.class, PDFOverrideFilters.class, TwoPAdESSigniatureMustHaveDifferentId.class,
		PAdESLevelBHuge.class, InvisibleSignatureFieldSign.class, PAdESSpaceEOF.class, PAdESDoubleLTAValidationData.class, PAdESNoDuplicateValidationData.class,
		BuildKnownObjects.class })
public class PAdESSignatureSuite {

}
