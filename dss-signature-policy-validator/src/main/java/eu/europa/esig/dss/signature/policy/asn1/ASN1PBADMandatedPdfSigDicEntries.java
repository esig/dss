/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.asn1;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import eu.europa.esig.dss.signature.policy.PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.signature.policy.PBADPdfEntry;

/**
 * 
 * MandatedPdfSigDicEntries ::= SEQUENCE OF PdfEntry
 * 
 * PdfEntry ::= SEQUENCE {
 *     id UTF8String (SIZE (1..MAX)),
 *     value OCTET STRING OPTIONAL – contém a codificação DER do conteúdo obrigatório da entrada
 * }
 * @author davyd.santos
 *
 */
public class ASN1PBADMandatedPdfSigDicEntries extends ASN1Object implements PBADMandatedPdfSigDicEntries {
	
	private List<PBADPdfEntry> requiredPdfEntries = new ArrayList<>();
	
	public static PBADMandatedPdfSigDicEntries getInstance(byte[] contents) {
		return getInstance(ASN1Sequence.getInstance(contents));
	}
	
	public static PBADMandatedPdfSigDicEntries getInstance(ASN1Object obj) {
		if (obj != null) {
			return new ASN1PBADMandatedPdfSigDicEntries(ASN1Sequence.getInstance(obj));
		}
		return null;
	}
	
	public ASN1PBADMandatedPdfSigDicEntries(ASN1Sequence as) {
		for (ASN1Encodable asn1Encodable : as) {
			requiredPdfEntries.add(new ASN1PBADPdfEntry(ASN1Sequence.getInstance(asn1Encodable)));
		}
	}
	
	public ASN1PBADMandatedPdfSigDicEntries(List<ASN1PBADPdfEntry> as) {
		requiredPdfEntries.addAll(as);
	}
	
	public ASN1PBADMandatedPdfSigDicEntries(ASN1PBADPdfEntry ... as) {
		this(Arrays.asList(as));
	}
	
	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(requiredPdfEntries);
	}
	
	/* (non-Javadoc)
	 * @see eu.europa.dss.signature.policy.asn1.PBADMandatedPdfSigDicEntries#getPdfEntries()
	 */
	@Override
	public List<PBADPdfEntry> getPdfEntries() {
		return Collections.unmodifiableList(requiredPdfEntries);
	}
}
