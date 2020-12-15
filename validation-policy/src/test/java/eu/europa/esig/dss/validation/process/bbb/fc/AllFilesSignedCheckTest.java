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
package eu.europa.esig.dss.validation.process.bbb.fc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AllFilesSignedCheck;

public class AllFilesSignedCheckTest extends AbstractTestCheck {

	@Test
	public void asicSValid() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
		
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Arrays.asList("file.txt"));

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		AllFilesSignedCheck afsc = new AllFilesSignedCheck(i18nProvider, result, new SignatureWrapper(sig), xmlContainerInfo, constraint);
		afsc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicSNoFiles() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
		
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		AllFilesSignedCheck afsc = new AllFilesSignedCheck(i18nProvider, result, new SignatureWrapper(sig), xmlContainerInfo, constraint);
		afsc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicSMultipleFiles() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
		
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Arrays.asList("file.txt", "bye.world"));

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		AllFilesSignedCheck afsc = new AllFilesSignedCheck(i18nProvider, result, new SignatureWrapper(sig), xmlContainerInfo, constraint);
		afsc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicEWithCAdESValid() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
		sig.setSignatureFilename("signature1");
		
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Arrays.asList("file.txt", "hello.world"));
		
		XmlManifestFile xmlManifestFile = new XmlManifestFile();
		xmlManifestFile.setSignatureFilename("signature1");
		xmlManifestFile.setEntries(Arrays.asList("file.txt", "hello.world"));
		xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, new XmlManifestFile()));

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		AllFilesSignedCheck afsc = new AllFilesSignedCheck(i18nProvider, result, new SignatureWrapper(sig), xmlContainerInfo, constraint);
		afsc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicEWithCAdESAnotherManifest() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
		sig.setSignatureFilename("signature1");
		
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Arrays.asList("file.txt", "hello.world"));
		
		XmlManifestFile xmlManifestFile = new XmlManifestFile();
		xmlManifestFile.setSignatureFilename("signature2");
		xmlManifestFile.setEntries(Arrays.asList("file.txt", "hello.world"));
		xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, new XmlManifestFile()));

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		AllFilesSignedCheck afsc = new AllFilesSignedCheck(i18nProvider, result, new SignatureWrapper(sig), xmlContainerInfo, constraint);
		afsc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicEWithCAdESNotMatchingContent() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
		sig.setSignatureFilename("signature1");
		
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Arrays.asList("file.txt", "hello.world"));
		
		XmlManifestFile xmlManifestFile = new XmlManifestFile();
		xmlManifestFile.setSignatureFilename("signature1");
		xmlManifestFile.setEntries(Arrays.asList("file.txt", "bye.world"));
		xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, new XmlManifestFile()));

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		AllFilesSignedCheck afsc = new AllFilesSignedCheck(i18nProvider, result, new SignatureWrapper(sig), xmlContainerInfo, constraint);
		afsc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicEWithXAdESValid() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);
		sig.setSignatureFilename("signature1");
		
		XmlSignatureScope xmlSignatureScope1 = new XmlSignatureScope();
		xmlSignatureScope1.setScope(SignatureScopeType.FULL);
		xmlSignatureScope1.setName("file.txt");
		
		XmlSignatureScope xmlSignatureScope2 = new XmlSignatureScope();
		xmlSignatureScope2.setScope(SignatureScopeType.FULL);
		xmlSignatureScope2.setName("hello.world");
		
		XmlSignatureScope xmlSignatureScope3 = new XmlSignatureScope();
		xmlSignatureScope3.setScope(SignatureScopeType.PARTIAL);
		xmlSignatureScope3.setName("r-id1");
		
		sig.setSignatureScopes(Arrays.asList(xmlSignatureScope1, xmlSignatureScope2, xmlSignatureScope3));
		
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Arrays.asList("file.txt", "hello.world"));
		
		XmlManifestFile xmlManifestFile = new XmlManifestFile();
		xmlManifestFile.setSignatureFilename("signature1");
		xmlManifestFile.setEntries(Arrays.asList("file.txt", "hello.world"));
		xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, new XmlManifestFile()));

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		AllFilesSignedCheck afsc = new AllFilesSignedCheck(i18nProvider, result, new SignatureWrapper(sig), xmlContainerInfo, constraint);
		afsc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicEWithXAdESInvalid() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);
		sig.setSignatureFilename("signature1");
		
		XmlSignatureScope xmlSignatureScope1 = new XmlSignatureScope();
		xmlSignatureScope1.setScope(SignatureScopeType.FULL);
		xmlSignatureScope1.setName("file.txt");
		
		XmlSignatureScope xmlSignatureScope2 = new XmlSignatureScope();
		xmlSignatureScope2.setScope(SignatureScopeType.PARTIAL);
		xmlSignatureScope2.setName("hello.world");
		
		XmlSignatureScope xmlSignatureScope3 = new XmlSignatureScope();
		xmlSignatureScope3.setScope(SignatureScopeType.PARTIAL);
		xmlSignatureScope3.setName("r-id1");
		
		sig.setSignatureScopes(Arrays.asList(xmlSignatureScope1, xmlSignatureScope2, xmlSignatureScope3));
		
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Arrays.asList("file.txt", "hello.world"));
		
		XmlManifestFile xmlManifestFile = new XmlManifestFile();
		xmlManifestFile.setSignatureFilename("signature1");
		xmlManifestFile.setEntries(Arrays.asList("file.txt", "hello.world"));
		xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, new XmlManifestFile()));

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		AllFilesSignedCheck afsc = new AllFilesSignedCheck(i18nProvider, result, new SignatureWrapper(sig), xmlContainerInfo, constraint);
		afsc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
