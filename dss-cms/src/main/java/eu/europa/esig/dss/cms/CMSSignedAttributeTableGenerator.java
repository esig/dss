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
package eu.europa.esig.dss.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;

import java.util.Hashtable;
import java.util.Map;

/**
 * CMS attributes table generator.
 * <p>
 * This class replicates a {@code org.bouncycastle.cms.DefaultAuthenticatedAttributeTableGenerator},
 * but without the signing-time attribute, that should be provided externally.
 * The class is used on both CMS for CAdES and CMS for PAdES generations.
 *
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public class CMSSignedAttributeTableGenerator implements CMSAttributeTableGenerator {

    /** The hashtable containing signing attributes  */
    private final Hashtable table;

    /**
     * Initialise with some extra attributes or overrides.
     *
     * @param attributeTable initial attribute table to use
     */
    public CMSSignedAttributeTableGenerator(AttributeTable attributeTable) {
        if (attributeTable != null) {
            table = new Hashtable(attributeTable.toHashtable());
        } else {
            table = new Hashtable();
        }
    }
    
    @Override
    public AttributeTable getAttributes(Map parameters) throws CMSAttributeTableGenerationException {
        return new AttributeTable(createStandardAttributeTable(parameters));
    }

    /**
     * Create a standard attribute table from the passed in parameters - this will
     * normally include contentType, signingTime, messageDigest, and CMS algorithm protection.
     * If the constructor using an AttributeTable was used, entries in it for contentType, signingTime, and
     * messageDigest will override the generated ones.
     *
     * @param parameters source parameters for table generation.
     *
     * @return a filled in Hashtable of attributes.
     */
    protected Hashtable createStandardAttributeTable(Map parameters) {

        if (!table.containsKey(CMSAttributes.contentType)) {
            ASN1ObjectIdentifier contentType = ASN1ObjectIdentifier.getInstance(parameters.get(CMSAttributeTableGenerator.CONTENT_TYPE));

            // contentType will be null if we're trying to generate a counter signature.
            if (contentType != null) {
                Attribute attr = new Attribute(CMSAttributes.contentType, new DERSet(contentType));
                table.put(attr.getAttrType(), attr);
            }
        }

        if (!table.containsKey(CMSAttributes.messageDigest)) {
            byte[] messageDigest = (byte[]) parameters.get(CMSAttributeTableGenerator.DIGEST);
            Attribute attr = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(messageDigest)));
            table.put(attr.getAttrType(), attr);
        }

        if (!table.contains(CMSAttributes.cmsAlgorithmProtect)) {
            Attribute attr = new Attribute(CMSAttributes.cmsAlgorithmProtect, new DERSet(new CMSAlgorithmProtection(
                    (AlgorithmIdentifier) parameters.get(CMSAttributeTableGenerator.DIGEST_ALGORITHM_IDENTIFIER),
                    CMSAlgorithmProtection.SIGNATURE, (AlgorithmIdentifier) parameters.get(CMSAttributeTableGenerator.SIGNATURE_ALGORITHM_IDENTIFIER))));
            table.put(attr.getAttrType(), attr);
        }

        return table;
    }
    
}
