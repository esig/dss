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
package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;

import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.junit.Test;
import org.w3c.dom.Attr;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.xades.SantuarioInitializer;

public class DetachedSignatureResolverTest {

	static {
		SantuarioInitializer.init();
	}

	@Test(expected = ResourceResolverException.class)
	public void nullAttribute() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Collections.<DSSDocument>emptyList(), DigestAlgorithm.SHA256);

		Attr attr = null;

		// Empty
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		// will throw ResourceResolverException
		resolver.engineResolveURI(context);
	}

	@Test(expected = ResourceResolverException.class)
	public void nullListAndNullAttribute() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(null, DigestAlgorithm.SHA256);

		Attr attr = null;

		// Empty
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		// will throw ResourceResolverException
		resolver.engineResolveURI(context);
	}

	@Test
	public void nullAttributeOneDoc() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Arrays.<DSSDocument>asList(new InMemoryDocument(new byte[] { 1, 2, 3 })),
				DigestAlgorithm.SHA256);

		Attr attr = null;

		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test(expected = ResourceResolverException.class)
	public void nullAttributeTwoDocs() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(
				Arrays.<DSSDocument> asList(new InMemoryDocument(new byte[] { 1, 2, 3 }), new InMemoryDocument(new byte[] { 2, 3 })), DigestAlgorithm.SHA256);

		Attr attr = null;

		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		// 2 docs + no name -> exception
		resolver.engineResolveURI(context);
	}

	@Test(expected = ResourceResolverException.class)
	public void emptyAttribute() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Collections.<DSSDocument>emptyList(), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		// Empty
		when(attr.getNodeValue()).thenReturn("");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertFalse(resolver.engineCanResolveURI(context));

		// will throw ResourceResolverException
		resolver.engineResolveURI(context);
	}

	@Test
	public void attributeIsAnchor() {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Collections.<DSSDocument>emptyList(), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("#id_tag");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertFalse(resolver.engineCanResolveURI(context));
	}

	@Test(expected = ResourceResolverException.class)
	public void documentNameWithEmptyList() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Collections.<DSSDocument>emptyList(), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		// document name + no document in the list
		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		// will throw ResourceResolverException
		resolver.engineResolveURI(context);
	}

	@Test(expected = ResourceResolverException.class)
	public void engineCanResolveURIWithWrongDocumentNameInList() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(
				Arrays.<DSSDocument>asList(new InMemoryDocument(new byte[] { 1, 2, 3 }, "toto.xml", MimeType.XML)),
				DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		// document name + wrong document in the list
		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		// doc not found -> exception
		resolver.engineResolveURI(context);
	}

	@Test
	public void engineCanResolveURIWithDocumentNoNameInList() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Arrays.<DSSDocument>asList(new InMemoryDocument(new byte[] { 1, 2, 3 })),
				DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		// document name + only one document
		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	public void engineCanResolveURIWithDocumentNameInList() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(
				Arrays.<DSSDocument>asList(new InMemoryDocument(new byte[] { 1, 2, 3 }, "sample.xml", MimeType.XML)),
				DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	public void engineCanResolveURIWithDocumentNameInListOfMultiples() throws ResourceResolverException {
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(
				Arrays.<DSSDocument>asList(new InMemoryDocument(new byte[] { 1, 2, 3 }, "sample.xml", MimeType.XML),
				new InMemoryDocument(new byte[] { 2, 3 }, "sample2.xml", MimeType.XML)), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	public void engineCanResolveURIWithDigestDocument() throws ResourceResolverException {
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA256, "abcdef");
		doc.setName("sample.xml");
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Arrays.<DSSDocument>asList(doc), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

	@Test
	public void engineCanResolveURIWithDigestDocumentNoName() throws ResourceResolverException {
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA256, "abcdef");
		// doc.setName("sample.xml");
		DetachedSignatureResolver resolver = new DetachedSignatureResolver(Arrays.<DSSDocument>asList(doc), DigestAlgorithm.SHA256);

		Attr attr = mock(Attr.class);

		when(attr.getNodeValue()).thenReturn("sample.xml");
		ResourceResolverContext context = new ResourceResolverContext(attr, null, false);
		assertTrue(resolver.engineCanResolveURI(context));

		assertNotNull(resolver.engineResolveURI(context));
	}

}
