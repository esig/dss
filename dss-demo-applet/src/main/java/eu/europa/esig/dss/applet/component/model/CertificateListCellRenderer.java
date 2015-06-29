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
package eu.europa.esig.dss.applet.component.model;

import java.awt.Component;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * 
 * TODO
 * 
 *
 *
 * 
 *
 *
 */
@SuppressWarnings("serial")
public class CertificateListCellRenderer extends DefaultListCellRenderer {
    /*
     * (non-Javadoc)
     * 
     * @see javax.swing.DefaultListCellRenderer#getListCellRendererComponent(javax.swing.JList, java.lang.Object, int,
     * boolean, boolean)
     */
    @Override
    public Component getListCellRendererComponent(final JList list, final Object value, final int index, final boolean isSelected, final boolean cellHasFocus) {
        final CertificateToken cert = ((DSSPrivateKeyEntry) value).getCertificate();
        String subjectDN = cert.getSubjectDN().getName();
        final int dnStartIndex = subjectDN.indexOf("CN=") + 3;
        if (dnStartIndex > 0 && subjectDN.indexOf(",", dnStartIndex) > 0) {
            subjectDN = subjectDN.substring(dnStartIndex, subjectDN.indexOf(",", dnStartIndex)) + " (SN:" + cert.getSerialNumber() + ")";
        }
        return super.getListCellRendererComponent(list, subjectDN, index, isSelected, cellHasFocus);
    }
}
